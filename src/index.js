import { importPKCS8, SignJWT, createRemoteJWKSet, jwtVerify } from 'jose';

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const FIREBASE_MESSAGING_SCOPE =
  'https://www.googleapis.com/auth/firebase.messaging';
const FIRESTORE_SCOPE =
  'https://www.googleapis.com/auth/datastore';

const FIREBASE_JWKS = createRemoteJWKSet(
  new URL(
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com',
  ),
);

let cachedAccessToken = null;
let cachedAccessTokenExpiresAt = 0;
let cachedServiceAccount = null;
let cachedProjectId = null;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

function cleanString(value) {
  return value == null ? '' : String(value).trim();
}

function base64UrlEncode(input) {
  const bytes =
    input instanceof Uint8Array
      ? input
      : new TextEncoder().encode(input);

  let binary = '';
  const chunk = 0x8000;

  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunk),
    );
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlDecode(value) {
  const normalized = value
    .replace(/-/g, '+')
    .replace(/_/g, '/');

  const padded =
    normalized +
    '='.repeat((4 - (normalized.length % 4)) % 4);

  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function parseServiceAccount(env) {
  if (cachedServiceAccount) {
    return cachedServiceAccount;
  }

  const raw = env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (!raw) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_JSON is not configured.',
    );
  }

  let parsed;

  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.',
    );
  }

  if (
    !parsed.project_id ||
    !parsed.client_email ||
    !parsed.private_key
  ) {
    throw new Error(
      'Firebase service account JSON is missing required fields.',
    );
  }

  parsed.private_key = parsed.private_key.replace(/\\n/g, '\n');

  cachedServiceAccount = parsed;
  cachedProjectId = parsed.project_id;

  return parsed;
}

async function createServiceAccountJwt(serviceAccount, scope) {
  const privateKey = await importPKCS8(
    serviceAccount.private_key,
    'RS256',
  );

  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({ scope })
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'JWT',
    })
    .setIssuer(serviceAccount.client_email)
    .setSubject(serviceAccount.client_email)
    .setAudience(GOOGLE_TOKEN_URL)
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(privateKey);
}

async function getGoogleAccessToken(env, scope) {
  const serviceAccount = parseServiceAccount(env);

  const cacheKey =
    `${serviceAccount.client_email}:${scope}`;

  if (
    cachedAccessToken &&
    cachedAccessToken.scope === cacheKey &&
    Date.now() < cachedAccessTokenExpiresAt - 60_000
  ) {
    return cachedAccessToken.value;
  }

  const assertion = await createServiceAccountJwt(
    serviceAccount,
    scope,
  );

  const response = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: {
      'content-type':
        'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type:
        'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });

  const body = await response
    .json()
    .catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      `Google OAuth token error (${response.status}): ${JSON.stringify(body)}`,
    );
  }

  cachedAccessToken = {
    value: body.access_token,
    scope: cacheKey,
  };

  cachedAccessTokenExpiresAt =
    Date.now() +
    Number(body.expires_in || 3600) * 1000;

  return body.access_token;
}

async function verifyFirebaseIdToken(env, idToken) {
  const projectId =
    parseServiceAccount(env).project_id;

  const { payload } = await jwtVerify(
    idToken,
    FIREBASE_JWKS,
    {
      issuer:
        `https://securetoken.google.com/${projectId}`,
      audience: projectId,
    },
  );

  if (
    !payload.sub ||
    typeof payload.sub !== 'string'
  ) {
    throw new Error(
      'Invalid Firebase ID token.',
    );
  }

  return payload;
}

function firestoreBase(projectId) {
  return (
    `https://firestore.googleapis.com/v1/projects/` +
    `${encodeURIComponent(projectId)}` +
    `/databases/(default)/documents`
  );
}

function firestoreValue(value) {
  if (value === null) {
    return { nullValue: null };
  }

  if (typeof value === 'boolean') {
    return { booleanValue: value };
  }

  if (typeof value === 'string') {
    return { stringValue: value };
  }

  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }

  return {
    stringValue: JSON.stringify(value),
  };
}

function decodeFirestoreValue(value) {
  if (
    !value ||
    typeof value !== 'object'
  ) {
    return null;
  }

  if ('stringValue' in value) {
    return value.stringValue;
  }

  if ('booleanValue' in value) {
    return value.booleanValue;
  }

  if ('integerValue' in value) {
    return Number(value.integerValue);
  }

  if ('doubleValue' in value) {
    return Number(value.doubleValue);
  }

  if ('timestampValue' in value) {
    return value.timestampValue;
  }

  if ('nullValue' in value) {
    return null;
  }

  if ('arrayValue' in value) {
    return (
      value.arrayValue.values || []
    ).map(decodeFirestoreValue);
  }

  if ('mapValue' in value) {
    const out = {};

    for (
      const [key, child] of Object.entries(
        value.mapValue.fields || {},
      )
    ) {
      out[key] = decodeFirestoreValue(child);
    }

    return out;
  }

  return null;
}

function decodeFirestoreDocument(document) {
  const out = {
    name: document.name,
  };

  for (
    const [key, value] of Object.entries(
      document.fields || {},
    )
  ) {
    out[key] = decodeFirestoreValue(value);
  }

  return out;
}

async function firestoreRequest(
  env,
  path,
  options = {},
) {
  const projectId =
    parseServiceAccount(env).project_id;

  const token =
    await getGoogleAccessToken(
      env,
      FIRESTORE_SCOPE,
    );

  const response = await fetch(
    `${firestoreBase(projectId)}${path}`,
    {
      ...options,
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        ...(options.headers || {}),
      },
    },
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Firestore error (${response.status}): ${text}`,
    );
  }

  return response;
}

async function getUser(env, uid) {
  const response =
    await firestoreRequest(
      env,
      `/users/${encodeURIComponent(uid)}`,
      {
        method: 'GET',
      },
    );

  return decodeFirestoreDocument(
    await response.json(),
  );
}

/**
 * Get all active FCM devices for a user.
 *
 * IMPORTANT:
 * Firestore REST runQuery can return
 * newline-delimited JSON instead of a
 * normal JSON array.
 */
async function getActiveDevices(env, uid) {
  const projectId =
    parseServiceAccount(env).project_id;

  const parent =
    `${firestoreBase(projectId)}` +
    `/users/${encodeURIComponent(uid)}`;

  const token =
    await getGoogleAccessToken(
      env,
      FIRESTORE_SCOPE,
    );

  const response = await fetch(
    `${parent}:runQuery`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        structuredQuery: {
          from: [
            {
              collectionId: 'devices',
            },
          ],

          where: {
            fieldFilter: {
              field: {
                fieldPath: 'isActive',
              },

              op: 'EQUAL',

              value: {
                booleanValue: true,
              },
            },
          },
        },
      }),
    },
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Firestore devices query error (${response.status}): ${text}`,
    );
  }

  // ------------------------------------------------------------
  // FIX:
  // Firestore runQuery may return newline-delimited JSON.
  // Do NOT use response.json() here.
  // ------------------------------------------------------------

  const text = await response.text();

  const rows = text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  return rows
    .filter((row) => row.document)
    .map((row) =>
      decodeFirestoreDocument(
        row.document,
      ),
    )
    .filter((doc) =>
      cleanString(doc.token),
    );
}

async function updateFirestoreDocuments(
  env,
  writes,
) {
  if (!writes.length) {
    return;
  }

  const projectId =
    parseServiceAccount(env).project_id;

  const token =
    await getGoogleAccessToken(
      env,
      FIRESTORE_SCOPE,
    );

  const response = await fetch(
    `https://firestore.googleapis.com/v1/projects/` +
      `${encodeURIComponent(projectId)}` +
      `/databases/(default)/documents:commit`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        writes,
      }),
    },
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Firestore commit error (${response.status}): ${text}`,
    );
  }
}

function buildData(notification) {
  const data = {
    notificationId:
      cleanString(notification.id),

    tournamentId:
      cleanString(notification.tournamentId),

    type:
      cleanString(notification.type),

    target:
      cleanString(notification.target),

    matchId:
      cleanString(notification.matchId),

    round:
      cleanString(notification.round),

    title:
      cleanString(notification.title),

    body:
      cleanString(notification.body),

    imageUrl:
      cleanString(notification.imageUrl),
  };

  const extra =
    notification.data;

  if (
    extra &&
    typeof extra === 'object' &&
    !Array.isArray(extra)
  ) {
    for (
      const [key, value] of Object.entries(
        extra,
      )
    ) {
      if (value == null) {
        continue;
      }

      data[`extra_${key}`] =
        typeof value === 'string'
          ? value
          : JSON.stringify(value);
    }
  }

  return data;
}

async function sendFcmMessage(
  env,
  token,
  notification,
) {
  const projectId =
    parseServiceAccount(env).project_id;

  const accessToken =
    await getGoogleAccessToken(
      env,
      FIREBASE_MESSAGING_SCOPE,
    );

  const message = {
    token,

    notification: {
      title:
        cleanString(notification.title) ||
        'Ptola',

      body:
        cleanString(notification.body),
    },

    data:
      buildData(notification),

    android: {
      priority: 'HIGH',

      notification: {
        channel_id:
          'ptola_notifications',

        sound: 'default',

        default_sound: true,

        default_vibrate_timings: true,

        notification_count: 1,
      },
    },

    apns: {
      payload: {
        aps: {
          sound: 'default',
        },
      },
    },
  };

  const response = await fetch(
    `https://fcm.googleapis.com/v1/projects/` +
      `${encodeURIComponent(projectId)}` +
      `/messages:send`,
    {
      method: 'POST',

      headers: {
        authorization:
          `Bearer ${accessToken}`,

        'content-type':
          'application/json; charset=UTF-8',
      },

      body: JSON.stringify({
        message,
      }),
    },
  );

  const body =
    await response
      .json()
      .catch(() => ({}));

  return {
    ok: response.ok,
    status: response.status,
    body,
  };
}

function isInvalidFcmToken(result) {
  if (
    !result ||
    result.ok
  ) {
    return false;
  }

  const message =
    JSON.stringify(
      result.body || '',
    ).toLowerCase();

  return (
    result.status === 404 ||
    message.includes(
      'registration-token-not-registered',
    ) ||
    message.includes(
      'unregistered',
    ) ||
    message.includes(
      'invalid-registration-token',
    )
  );
}

async function sendToRecipient(
  env,
  notification,
) {
  const recipientUid =
    cleanString(
      notification.recipientUid,
    );

  if (!recipientUid) {
    throw new Error(
      'recipientUid is required.',
    );
  }

  const devices =
    await getActiveDevices(
      env,
      recipientUid,
    );

  const uniqueDevices = [
    ...new Map(
      devices.map((device) => [
        device.token,
        device,
      ]),
    ).values(),
  ];

  if (!uniqueDevices.length) {
    return {
      successCount: 0,
      failureCount: 0,
      invalidDeviceIds: [],
    };
  }

  const results =
    await Promise.all(
      uniqueDevices.map(
        async (device) => {
          try {
            const result =
              await sendFcmMessage(
                env,
                device.token,
                notification,
              );

            return {
              device,
              result,
            };
          } catch (error) {
            return {
              device,

              result: {
                ok: false,
                status: 500,

                body: {
                  error:
                    error.message,
                },
              },
            };
          }
        },
      ),
    );

  const successCount =
    results.filter(
      ({ result }) => result.ok,
    ).length;

  const failureCount =
    results.length -
    successCount;

  const invalidDevices =
    results.filter(
      ({ result }) =>
        isInvalidFcmToken(result),
    );

  if (
    invalidDevices.length
  ) {
    const writes =
      invalidDevices.map(
        ({ device }) => ({
          update: {
            name: device.name,

            fields: {
              isActive: {
                booleanValue: false,
              },
            },
          },

          updateMask: {
            fieldPaths: [
              'isActive',
            ],
          },

          updateTransforms: [
            {
              fieldPath:
                'disabledAt',

              setToServerValue:
                'REQUEST_TIME',
            },
          ],
        }),
      );

    await updateFirestoreDocuments(
      env,
      writes,
    );
  }

  return {
    successCount,
    failureCount,

    invalidDeviceIds:
      invalidDevices.map(
        ({ device }) =>
          device.name,
      ),
  };
}

async function authenticateAdmin(
  env,
  request,
) {
  const header =
    request.headers.get(
      'authorization',
    ) || '';

  if (
    !header.startsWith(
      'Bearer ',
    )
  ) {
    const error =
      new Error(
        'Missing Firebase ID token.',
      );

    error.statusCode = 401;

    throw error;
  }

  const idToken =
    header
      .slice('Bearer '.length)
      .trim();

  if (!idToken) {
    const error =
      new Error(
        'Empty Firebase ID token.',
      );

    error.statusCode = 401;

    throw error;
  }

  const decoded =
    await verifyFirebaseIdToken(
      env,
      idToken,
    );

  const user =
    await getUser(
      env,
      decoded.sub,
    );

  if (
    user.role !== 'admin'
  ) {
    const error =
      new Error(
        'Admin access required.',
      );

    error.statusCode = 403;

    throw error;
  }

  return decoded;
}

async function handleSend(
  env,
  request,
) {
  await authenticateAdmin(
    env,
    request,
  );

  const body =
    await request
      .json()
      .catch(() => null);

  const notification =
    body?.notification;

  if (
    !notification ||
    typeof notification !== 'object' ||
    Array.isArray(notification)
  ) {
    return json(
      {
        ok: false,
        error:
          'notification object is required.',
      },
      400,
    );
  }

  const notificationId =
    cleanString(
      notification.id,
    );

  if (!notificationId) {
    return json(
      {
        ok: false,
        error:
          'notification.id is required.',
      },
      400,
    );
  }

  const result =
    await sendToRecipient(
      env,
      notification,
    );

  const projectId =
    parseServiceAccount(env).project_id;

  const notificationPath =
    `${firestoreBase(projectId)}` +
    `/notifications/` +
    `${encodeURIComponent(notificationId)}`;

  const notificationFields = {
    pushStatus:
      firestoreValue(
        result.successCount > 0
          ? 'sent'
          : 'failed',
      ),

    pushSuccessCount:
      firestoreValue(
        result.successCount,
      ),

    pushFailureCount:
      firestoreValue(
        result.failureCount,
      ),
  };

  const writes = [
    {
      update: {
        name:
          notificationPath,

        fields:
          notificationFields,
      },

      updateMask: {
        fieldPaths:
          Object.keys(
            notificationFields,
          ),
      },

      updateTransforms: [
        {
          fieldPath:
            'pushSentAt',

          setToServerValue:
            'REQUEST_TIME',
        },
      ],
    },
  ];

  await updateFirestoreDocuments(
    env,
    writes,
  );

  return json({
    ok: true,

    notificationId,

    ...result,
  });
}

export default {
  async fetch(
    request,
    env,
  ) {
    try {
      const url =
        new URL(
          request.url,
        );

      if (
        request.method === 'GET' &&
        url.pathname === '/health'
      ) {
        return json({
          ok: true,
          service:
            'ptola-notification-backend',
        });
      }

      if (
        request.method === 'POST' &&
        url.pathname ===
          '/v1/notifications/send'
      ) {
        return await handleSend(
          env,
          request,
        );
      }

      return json(
        {
          ok: false,
          error: 'Not found.',
        },
        404,
      );
    } catch (error) {
      console.error(error);

      const status =
        Number(
          error.statusCode,
        ) || 500;

      return json(
        {
          ok: false,

          error:
            error?.message ||
            'Internal server error.',
        },
        status,
      );
    }
  },
};
