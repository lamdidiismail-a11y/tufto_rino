const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const multer = require("multer");
require("dotenv").config();

const db = require("./config/db");

const app = express();
const dbPromise = db.promise();
const PORT = process.env.PORT || 5000;
const AUTH_SECRET = process.env.AUTH_SECRET || "tufto-rino-admin-secret";
const ADMIN_STATUS_VALUES = new Set(["pending", "paid", "shipped"]);
const CONVERSATION_STATUS_VALUES = new Set(["open", "pending", "closed"]);
const uploadsRoot = path.join(__dirname, "uploads");
const customRequestUploadsDir = path.join(uploadsRoot, "custom-requests");
const messageUploadsDir = path.join(uploadsRoot, "messages");
const productUploadsDir = path.join(uploadsRoot, "products");

fs.mkdirSync(customRequestUploadsDir, { recursive: true });
fs.mkdirSync(messageUploadsDir, { recursive: true });
fs.mkdirSync(productUploadsDir, { recursive: true });

const customRequestStorage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, customRequestUploadsDir);
  },
  filename: (req, file, callback) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const safeExtension = extension || ".jpg";
    callback(null, `custom-request-${Date.now()}-${Math.round(Math.random() * 1e9)}${safeExtension}`);
  },
});

const uploadCustomRequestImage = multer({
  storage: customRequestStorage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (req, file, callback) => {
    if (file.mimetype && file.mimetype.startsWith("image/")) {
      callback(null, true);
      return;
    }

    callback(new Error("Seules les images sont autorisées"));
  },
});

const messageAttachmentStorage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, messageUploadsDir);
  },
  filename: (req, file, callback) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const safeExtension = extension || ".bin";
    callback(null, `message-${Date.now()}-${Math.round(Math.random() * 1e9)}${safeExtension}`);
  },
});

const uploadMessageAttachment = multer({
  storage: messageAttachmentStorage,
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
  fileFilter: (req, file, callback) => {
    const allowedMimeTypes = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      callback(null, true);
      return;
    }

    callback(new Error("Type de fichier non autorise"));
  },
});

const productImageStorage = multer.diskStorage({
  destination: (req, file, callback) => {
    callback(null, productUploadsDir);
  },
  filename: (req, file, callback) => {
    const extension = path.extname(file.originalname || "").toLowerCase();
    const safeExtension = extension || ".jpg";
    callback(null, `product-${Date.now()}-${Math.round(Math.random() * 1e9)}${safeExtension}`);
  },
});

const uploadProductImage = multer({
  storage: productImageStorage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (req, file, callback) => {
    if (file.mimetype && file.mimetype.startsWith("image/")) {
      callback(null, true);
      return;
    }

    callback(new Error("Seules les images sont autorisées"));
  },
});

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: false,
  })
);
app.use(express.json());
app.use("/uploads", express.static(uploadsRoot));

console.log("✅ ROUTES LOADED FROM THIS server.js");

app.get("/api/test-route", (req, res) => {
  res.json({ success: true, message: "Backend OK" });
});

app.get("/api/categories", async (req, res) => {
  try {
    const [categories] = await dbPromise.query(`
      SELECT id, name
      FROM categories
      ORDER BY name ASC
    `);

    res.json(categories);
  } catch (error) {
    console.error("Erreur GET /api/categories:", error);
    res.status(500).json({
      success: false,
      error: "Erreur serveur categories",
      details: error.message,
    });
  }
});

const asyncHandler =
  (handler) =>
  (req, res, next) =>
    Promise.resolve(handler(req, res, next)).catch((error) => {
      console.error(error);
      res.status(500).json({
        success: false,
        message: "Server error",
      });
    });

function createAuthToken(user) {
  const payload = {
    id: user.id,
    email: user.email,
    role: user.role,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encodedPayload)
    .digest("base64url");

  return `${encodedPayload}.${signature}`;
}

function verifyAuthToken(token) {
  if (!token || !token.includes(".")) {
    return null;
  }

  const [encodedPayload, providedSignature] = token.split(".");
  const expectedSignature = crypto
    .createHmac("sha256", AUTH_SECRET)
    .update(encodedPayload)
    .digest("base64url");

  if (providedSignature !== expectedSignature) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    if (!payload.exp || payload.exp < Date.now()) {
      return null;
    }
    return payload;
  } catch (error) {
    return null;
  }
}

function normalizeUser(user) {
  return {
    id: user.id,
    name: user.full_name,
    email: user.email,
    role: user.role,
  };
}

function extractToken(req) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return null;
  }
  return authHeader.slice(7);
}

function requireAuth(req, res, next) {
  const token = extractToken(req);
  const authUser = verifyAuthToken(token);

  if (!authUser) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized",
    });
  }

  req.authUser = authUser;
  next();
}

function requireAdmin(req, res, next) {
  const token = extractToken(req);
  const authUser = verifyAuthToken(token);

  if (!authUser) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized",
    });
  }

  if (authUser.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Forbidden",
    });
  }

  req.authUser = authUser;
  next();
}

function customRequestUploadMiddleware(req, res, next) {
  uploadCustomRequestImage.single("image")(req, res, (error) => {
    if (!error) {
      next();
      return;
    }

    if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
      res.status(400).json({
        success: false,
        message: "L'image ne doit pas dépasser 5 Mo",
      });
      return;
    }

    res.status(400).json({
      success: false,
      message: error.message || "Erreur lors du téléversement de l'image",
    });
  });
}

function messageUploadMiddleware(req, res, next) {
  uploadMessageAttachment.single("attachment")(req, res, (error) => {
    if (!error) {
      next();
      return;
    }

    if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
      res.status(400).json({
        success: false,
        message: "La piece jointe ne doit pas depasser 10 Mo",
      });
      return;
    }

    res.status(400).json({
      success: false,
      message: error.message || "Erreur lors du televersement de la piece jointe",
    });
  });
}

function productUploadMiddleware(req, res, next) {
  uploadProductImage.single("image")(req, res, (error) => {
    if (!error) {
      next();
      return;
    }

    if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
      res.status(400).json({
        success: false,
        message: "L'image du produit ne doit pas dépasser 5 Mo",
      });
      return;
    }

    res.status(400).json({
      success: false,
      message: error.message || "Erreur lors du téléversement de l'image du produit",
    });
  });
}

function normalizeCustomRequest(row) {
  const storedImage = row.image || row.image_path || null;

  return {
    id: row.id,
    userId: row.user_id,
    conversationId: row.conversation_id || null,
    title: row.title,
    description: row.description,
    dimensions: row.dimensions || "",
    colors: row.colors || "",
    budget: row.budget || "",
    phone: row.phone || "",
    image: storedImage,
    imageUrl: storedImage ? `http://localhost:${PORT}${storedImage}` : null,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at || row.created_at,
  };
}

function normalizeAdminMessage(row) {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    clientName: row.client_name,
    email: row.client_email,
    subject: row.subject || null,
    content: row.message,
    messageType: row.message_type,
    status: row.status || null,
    createdAt: row.created_at,
  };
}

function normalizeConversation(row) {
  return {
    id: row.id,
    clientId: row.client_id,
    adminId: row.admin_id,
    subject: row.subject || "Conversation sans objet",
    status: row.status || "open",
    orderId: row.order_id || null,
    customRequestId: row.custom_request_id || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at || row.created_at,
    lastMessage: row.last_message || "",
    lastMessageAt: row.last_message_at || row.updated_at || row.created_at,
    lastMessageType: row.last_message_type || "text",
    messageCount: Number(row.message_count || 0),
    client: row.client_name
      ? {
          id: row.client_id,
          name: row.client_name,
          email: row.client_email,
        }
      : null,
    admin: row.admin_name
      ? {
          id: row.admin_id,
          name: row.admin_name,
          email: row.admin_email,
        }
      : null,
  };
}

function normalizeConversationMessage(row, authUser) {
  const isOwnMessage = authUser ? Number(row.sender_id) === Number(authUser.id) : false;

  return {
    id: row.id,
    conversationId: row.conversation_id,
    senderId: row.sender_id,
    senderRole: row.sender_role || row.user_role || "client",
    senderName: row.sender_name,
    senderEmail: row.sender_email,
    content: row.message || "",
    messageType: row.message_type || "text",
    createdAt: row.created_at,
    isOwnMessage,
    attachments: [],
  };
}

function attachMessageAttachments(messages, attachments) {
  const attachmentsByMessageId = attachments.reduce((accumulator, attachment) => {
    const normalizedAttachment = {
      id: attachment.id,
      messageId: attachment.message_id,
      filePath: attachment.file_path,
      filename: attachment.filename || path.basename(attachment.file_path || ""),
      mimeType: attachment.mime_type || "application/octet-stream",
      createdAt: attachment.created_at,
      url: attachment.file_path ? `http://localhost:${PORT}${attachment.file_path}` : null,
    };

    if (!accumulator.has(attachment.message_id)) {
      accumulator.set(attachment.message_id, []);
    }

    accumulator.get(attachment.message_id).push(normalizedAttachment);
    return accumulator;
  }, new Map());

  return messages.map((message) => ({
    ...message,
    attachments: attachmentsByMessageId.get(message.id) || [],
  }));
}

function normalizeConversationStatus(status) {
  return String(status || "open").trim().toLowerCase();
}

function normalizeProduct(product) {
  const rawImage = product.image || null;
  const image =
    rawImage && /^https?:\/\//i.test(rawImage)
      ? rawImage
      : rawImage && rawImage.startsWith("/uploads/")
        ? `http://localhost:${PORT}${rawImage}`
        : rawImage
          ? `http://localhost:${PORT}/uploads/${rawImage}`
          : null;
  const categoryId = product.category_id ?? product.categoryId ?? null;
  const categoryName = product.category_name || product.categoryName || null;
  const createdAt = product.created_at || product.createdAt || null;

  return {
    ...product,
    category_id: categoryId,
    categoryId,
    category_name: categoryName,
    categoryName,
    price: Number(product.price || 0),
    stock: Number(product.stock || 0),
    dimensions: product.dimensions || "",
    created_at: createdAt,
    createdAt,
    image,
  };
}

const PRODUCT_SELECT_FIELDS = `
  SELECT
    p.id,
    p.category_id,
    c.name AS category_name,
    p.name,
    p.description,
    p.dimensions,
    p.price,
    p.image,
    p.stock,
    p.created_at
  FROM products p
  LEFT JOIN categories c ON c.id = p.category_id
`;

async function ensureProductSchema() {
  await dbPromise.query(`
    CREATE TABLE IF NOT EXISTS categories (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL UNIQUE
    )
  `);

  const [columns] = await dbPromise.query("SHOW COLUMNS FROM products");
  const columnNames = new Set(columns.map((column) => column.Field));
  const alterStatements = [];

  if (!columnNames.has("category_id")) {
    alterStatements.push("ADD COLUMN category_id INT(11) NULL AFTER id");
  }

  if (!columnNames.has("dimensions")) {
    alterStatements.push("ADD COLUMN dimensions VARCHAR(255) NULL AFTER description");
  }

  if (alterStatements.length > 0) {
    await dbPromise.query(`ALTER TABLE products ${alterStatements.join(", ")}`);
  }
}

async function ensureCategorySeed() {
  const categoryNames = [
    "Anime",
    "Cartoon",
    "Gaming",
    "Mark or brand",
    "Barber",
    "Football",
    "Name",
    "Tapis voiture",
    "Tapis souris",
  ];

  for (const categoryName of categoryNames) {
    await dbPromise.query(
      `
        INSERT INTO categories (name)
        SELECT ?
        FROM DUAL
        WHERE NOT EXISTS (
          SELECT 1
          FROM categories
          WHERE LOWER(name) = LOWER(?)
        )
      `,
      [categoryName, categoryName]
    );
  }
}

async function ensureOrderSchema() {
  const [columns] = await dbPromise.query("SHOW COLUMNS FROM orders");
  const columnNames = new Set(columns.map((column) => column.Field));
  const alterStatements = [];

  if (!columnNames.has("payment_method")) {
    alterStatements.push("ADD COLUMN payment_method VARCHAR(50) NULL AFTER address");
  }

  if (!columnNames.has("payment_status")) {
    alterStatements.push("ADD COLUMN payment_status VARCHAR(50) NULL AFTER payment_method");
  }

  if (!columnNames.has("updated_at")) {
    alterStatements.push(
      "ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp() AFTER created_at"
    );
  }

  if (alterStatements.length > 0) {
    await dbPromise.query(`ALTER TABLE orders ${alterStatements.join(", ")}`);
  }
}

async function ensureCustomRequestSchema() {
  const [columns] = await dbPromise.query("SHOW COLUMNS FROM custom_requests");
  const columnNames = new Set(columns.map((column) => column.Field));
  const alterStatements = [];

  if (!columnNames.has("dimensions")) {
    alterStatements.push("ADD COLUMN dimensions VARCHAR(255) NULL AFTER description");
  }

  if (!columnNames.has("colors")) {
    alterStatements.push("ADD COLUMN colors VARCHAR(255) NULL AFTER dimensions");
  }

  if (!columnNames.has("budget")) {
    alterStatements.push("ADD COLUMN budget VARCHAR(120) NULL AFTER colors");
  }

  if (!columnNames.has("phone")) {
    alterStatements.push("ADD COLUMN phone VARCHAR(50) NULL AFTER budget");
  }

  if (!columnNames.has("image")) {
    alterStatements.push("ADD COLUMN image VARCHAR(255) NULL AFTER phone");
  }

  if (!columnNames.has("updated_at")) {
    alterStatements.push(
      "ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp() AFTER created_at"
    );
  }

  if (!columnNames.has("conversation_id")) {
    alterStatements.push("ADD COLUMN conversation_id INT(11) NULL AFTER status");
  }

  if (alterStatements.length > 0) {
    await dbPromise.query(`ALTER TABLE custom_requests ${alterStatements.join(", ")}`);
  }
}

async function ensureConversationSchema() {
  const [columns] = await dbPromise.query("SHOW COLUMNS FROM conversations");
  const columnNames = new Set(columns.map((column) => column.Field));
  const alterStatements = [];

  if (!columnNames.has("subject")) {
    alterStatements.push("ADD COLUMN subject VARCHAR(255) NULL AFTER admin_id");
  }

  if (!columnNames.has("status")) {
    alterStatements.push("ADD COLUMN status VARCHAR(30) NOT NULL DEFAULT 'open' AFTER subject");
  }

  if (!columnNames.has("updated_at")) {
    alterStatements.push(
      "ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp() AFTER created_at"
    );
  }

  if (alterStatements.length > 0) {
    await dbPromise.query(`ALTER TABLE conversations ${alterStatements.join(", ")}`);
  }
}

async function ensureMessagesSchema() {
  const [columns] = await dbPromise.query("SHOW COLUMNS FROM messages");
  const columnNames = new Set(columns.map((column) => column.Field));
  const alterStatements = [];

  if (!columnNames.has("sender_role")) {
    alterStatements.push("ADD COLUMN sender_role VARCHAR(20) NULL AFTER sender_id");
  }

  if (alterStatements.length > 0) {
    await dbPromise.query(`ALTER TABLE messages ${alterStatements.join(", ")}`);
  }

  await dbPromise.query(
    `
      UPDATE messages m
      INNER JOIN users u ON u.id = m.sender_id
      SET m.sender_role = u.role
      WHERE m.sender_role IS NULL OR m.sender_role = ''
    `
  );
}

async function ensureMessageAttachmentsSchema() {
  const [columns] = await dbPromise.query("SHOW COLUMNS FROM message_attachments");
  const columnNames = new Set(columns.map((column) => column.Field));
  const alterStatements = [];

  if (!columnNames.has("filename")) {
    alterStatements.push("ADD COLUMN filename VARCHAR(255) NULL AFTER file_path");
  }

  if (!columnNames.has("mime_type")) {
    alterStatements.push("ADD COLUMN mime_type VARCHAR(120) NULL AFTER filename");
  }

  if (!columnNames.has("file_size")) {
    alterStatements.push("ADD COLUMN file_size INT(11) NULL AFTER mime_type");
  }

  if (alterStatements.length > 0) {
    await dbPromise.query(`ALTER TABLE message_attachments ${alterStatements.join(", ")}`);
  }
}

async function getOrCreateCartId(userId, connection = dbPromise) {
  const [existingCarts] = await connection.query(
    "SELECT id FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
    [userId]
  );

  if (existingCarts.length > 0) {
    return existingCarts[0].id;
  }

  const [result] = await connection.query("INSERT INTO carts (user_id) VALUES (?)", [userId]);
  return result.insertId;
}

function buildCartResponse(items) {
  const normalizedItems = items.map((item) => {
    const quantity = Number(item.quantity || 0);
    const unitPrice = Number(item.unitPrice || 0);
    const lineTotal = Number((unitPrice * quantity).toFixed(2));

    return {
      id: item.id,
      cartId: item.cartId,
      productId: item.productId,
      quantity,
      product: {
        id: item.productId,
        name: item.name,
        description: item.description,
        image: item.image,
        categoryId: item.categoryId,
        categoryName: item.categoryName,
        stock: Number(item.stock || 0),
        price: unitPrice,
      },
      unitPrice,
      lineTotal,
    };
  });

  const subtotal = Number(
    normalizedItems.reduce((sum, item) => sum + item.lineTotal, 0).toFixed(2)
  );
  const totalQuantity = normalizedItems.reduce((sum, item) => sum + item.quantity, 0);

  return {
    items: normalizedItems,
    summary: {
      subtotal,
      total: subtotal,
      totalQuantity,
      itemCount: normalizedItems.length,
    },
  };
}

async function getCartByUser(userId, options = {}) {
  const connection = options.connection || dbPromise;
  const ensureCart = options.ensureCart ?? false;

  const [carts] = await connection.query(
    "SELECT id FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
    [userId]
  );

  let cartId = carts[0]?.id || null;

  if (!cartId && ensureCart) {
    cartId = await getOrCreateCartId(userId, connection);
  }

  if (!cartId) {
    return {
      cartId: null,
      items: [],
      summary: {
        subtotal: 0,
        total: 0,
        totalQuantity: 0,
        itemCount: 0,
      },
    };
  }

  const [items] = await connection.query(
    `
      SELECT
        ci.id,
        ci.cart_id AS cartId,
        ci.product_id AS productId,
        ci.quantity,
        p.name,
        p.description,
        p.image,
        p.price AS unitPrice,
        p.stock,
        p.category_id AS categoryId,
        c.name AS categoryName
      FROM cart_items ci
      INNER JOIN products p ON p.id = ci.product_id
      LEFT JOIN categories c ON c.id = p.category_id
      WHERE ci.cart_id = ?
      ORDER BY ci.id DESC
    `,
    [cartId]
  );

  return {
    cartId,
    ...buildCartResponse(items),
  };
}

async function getDashboardStats() {
  const [[productsCount], [ordersCount], [usersCount], [customRequestsCount]] = await Promise.all([
    dbPromise.query("SELECT COUNT(*) AS totalProducts FROM products"),
    dbPromise.query("SELECT COUNT(*) AS totalOrders FROM orders"),
    dbPromise.query("SELECT COUNT(*) AS totalUsers FROM users"),
    dbPromise.query("SELECT COUNT(*) AS totalCustomRequests FROM custom_requests"),
  ]).then((results) => results.map(([rows]) => rows));

  return {
    totalProducts: productsCount.totalProducts,
    totalOrders: ordersCount.totalOrders,
    totalUsers: usersCount.totalUsers,
    totalCustomRequests: customRequestsCount.totalCustomRequests,
  };
}

function mapDbStatusToAdmin(status) {
  if (status === "shipped" || status === "delivered") {
    return "shipped";
  }

  if (status === "confirmed" || status === "processing") {
    return "paid";
  }

  return "pending";
}

function mapAdminStatusToDb(status) {
  if (status === "paid") {
    return "confirmed";
  }

  if (status === "shipped") {
    return "shipped";
  }

  return "pending";
}

async function getOrders(limitClause = "") {
  const [rows] = await dbPromise.query(
    `
      SELECT
        o.id,
        u.full_name AS client,
        u.email,
        o.total,
        o.status,
        o.order_type AS orderType,
        o.created_at AS createdAt,
        CASE
          WHEN o.order_type = 'custom' THEN COALESCE(cr.title, 'Custom request')
          ELSE COALESCE(
            (
              SELECT
                CASE
                  WHEN COUNT(*) = 0 THEN 'Catalog order'
                  WHEN COUNT(*) = 1 THEN MAX(p.name)
                  ELSE CONCAT(MAX(p.name), ' +', COUNT(*) - 1, ' more')
                END
              FROM order_items oi
              INNER JOIN products p ON p.id = oi.product_id
              WHERE oi.order_id = o.id
            ),
            'Catalog order'
          )
        END AS summary
      FROM orders o
      INNER JOIN users u ON u.id = o.user_id
      LEFT JOIN custom_requests cr ON cr.id = o.custom_request_id
      ORDER BY o.created_at DESC
      ${limitClause}
    `
  );

  return rows.map((row) => ({
    id: row.id,
    client: row.client,
    email: row.email,
    total: Number(row.total || 0),
    status: mapDbStatusToAdmin(row.status),
    rawStatus: row.status,
    orderType: row.orderType,
    summary: row.summary,
    date: row.createdAt,
  }));
}

function safeParseJson(value, fallback = {}) {
  if (!value) {
    return fallback;
  }

  try {
    return JSON.parse(value);
  } catch (error) {
    return fallback;
  }
}

async function getClientOrders(userId) {
  const [rows] = await dbPromise.query(
    `
      SELECT
        o.id,
        o.total,
        o.status,
        o.payment_method AS paymentMethod,
        o.payment_status AS paymentStatus,
        o.created_at AS createdAt,
        COUNT(oi.id) AS itemCount
      FROM orders o
      LEFT JOIN order_items oi ON oi.order_id = o.id
      WHERE o.user_id = ?
      GROUP BY o.id
      ORDER BY o.created_at DESC, o.id DESC
    `,
    [userId]
  );

  return rows.map((row) => ({
    id: row.id,
    total: Number(row.total || 0),
    status: row.status || "pending",
    paymentMethod: row.paymentMethod || "livraison",
    paymentStatus: row.paymentStatus || null,
    createdAt: row.createdAt,
    itemCount: Number(row.itemCount || 0),
  }));
}

async function getClientOrderById(orderId, userId) {
  const [orders] = await dbPromise.query(
    `
      SELECT
        o.id,
        o.total,
        o.status,
        o.payment_method AS paymentMethod,
        o.payment_status AS paymentStatus,
        o.address,
        o.created_at AS createdAt
      FROM orders o
      WHERE o.id = ? AND o.user_id = ?
      LIMIT 1
    `,
    [orderId, userId]
  );

  if (orders.length === 0) {
    return null;
  }

  const order = orders[0];
  const [items] = await dbPromise.query(
    `
      SELECT
        oi.id,
        oi.quantity,
        oi.price,
        p.id AS productId,
        p.name,
        p.image
      FROM order_items oi
      LEFT JOIN products p ON p.id = oi.product_id
      WHERE oi.order_id = ?
      ORDER BY oi.id ASC
    `,
    [orderId]
  );

  return {
    id: order.id,
    total: Number(order.total || 0),
    status: order.status || "pending",
    paymentMethod: order.paymentMethod || "livraison",
    paymentStatus: order.paymentStatus || null,
    createdAt: order.createdAt,
    delivery: safeParseJson(order.address, {}),
    items: items.map((item) => ({
      id: item.id,
      productId: item.productId,
      name: item.name || "Produit",
      image: item.image || null,
      quantity: Number(item.quantity || 0),
      price: Number(item.price || 0),
    })),
  };
}

async function getFirstAdminUserId(connection = dbPromise) {
  const [admins] = await connection.query(
    "SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1"
  );
  return admins[0]?.id || null;
}

async function getConversationById(conversationId, options = {}) {
  const connection = options.connection || dbPromise;
  const [rows] = await connection.query(
    `
      SELECT
        c.*,
        client.full_name AS client_name,
        client.email AS client_email,
        admin.full_name AS admin_name,
        admin.email AS admin_email,
        (
          SELECT m2.message
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT m2.created_at
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message_at,
        (
          SELECT m2.message_type
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message_type,
        (
          SELECT COUNT(*)
          FROM messages m3
          WHERE m3.conversation_id = c.id
        ) AS message_count
      FROM conversations c
      LEFT JOIN users client ON client.id = c.client_id
      LEFT JOIN users admin ON admin.id = c.admin_id
      WHERE c.id = ?
      LIMIT 1
    `,
    [conversationId]
  );

  if (rows.length === 0) {
    return null;
  }

  return normalizeConversation(rows[0]);
}

async function getConversationsForUser(userId) {
  const [rows] = await dbPromise.query(
    `
      SELECT
        c.*,
        client.full_name AS client_name,
        client.email AS client_email,
        admin.full_name AS admin_name,
        admin.email AS admin_email,
        (
          SELECT m2.message
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT m2.created_at
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message_at,
        (
          SELECT m2.message_type
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message_type,
        (
          SELECT COUNT(*)
          FROM messages m3
          WHERE m3.conversation_id = c.id
        ) AS message_count
      FROM conversations c
      LEFT JOIN users client ON client.id = c.client_id
      LEFT JOIN users admin ON admin.id = c.admin_id
      WHERE c.client_id = ?
      ORDER BY COALESCE(
        (
          SELECT MAX(m4.created_at)
          FROM messages m4
          WHERE m4.conversation_id = c.id
        ),
        c.updated_at,
        c.created_at
      ) DESC, c.id DESC
    `,
    [userId]
  );

  return rows.map(normalizeConversation);
}

async function getAdminConversations(status) {
  const params = [];
  let statusClause = "";

  if (status && CONVERSATION_STATUS_VALUES.has(status)) {
    statusClause = "WHERE c.status = ?";
    params.push(status);
  }

  const [rows] = await dbPromise.query(
    `
      SELECT
        c.*,
        client.full_name AS client_name,
        client.email AS client_email,
        admin.full_name AS admin_name,
        admin.email AS admin_email,
        (
          SELECT m2.message
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message,
        (
          SELECT m2.created_at
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message_at,
        (
          SELECT m2.message_type
          FROM messages m2
          WHERE m2.conversation_id = c.id
          ORDER BY m2.created_at DESC, m2.id DESC
          LIMIT 1
        ) AS last_message_type,
        (
          SELECT COUNT(*)
          FROM messages m3
          WHERE m3.conversation_id = c.id
        ) AS message_count
      FROM conversations c
      LEFT JOIN users client ON client.id = c.client_id
      LEFT JOIN users admin ON admin.id = c.admin_id
      ${statusClause}
      ORDER BY COALESCE(
        (
          SELECT MAX(m4.created_at)
          FROM messages m4
          WHERE m4.conversation_id = c.id
        ),
        c.updated_at,
        c.created_at
      ) DESC, c.id DESC
    `,
    params
  );

  return rows.map(normalizeConversation);
}

async function assertConversationAccess(conversationId, authUser, options = {}) {
  const forAdmin = options.forAdmin || false;
  const conversation = await getConversationById(conversationId, options);

  if (!conversation) {
    return null;
  }

  if (forAdmin) {
    return conversation;
  }

  if (Number(conversation.clientId) !== Number(authUser.id)) {
    return false;
  }

  return conversation;
}

async function getConversationMessages(conversationId, authUser) {
  const [rows] = await dbPromise.query(
    `
      SELECT
        m.*,
        u.full_name AS sender_name,
        u.email AS sender_email,
        u.role AS user_role
      FROM messages m
      INNER JOIN users u ON u.id = m.sender_id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC, m.id ASC
    `,
    [conversationId]
  );

  const normalizedMessages = rows.map((row) => normalizeConversationMessage(row, authUser));

  if (normalizedMessages.length === 0) {
    return [];
  }

  const messageIds = normalizedMessages.map((message) => message.id);
  const [attachments] = await dbPromise.query(
    `
      SELECT *
      FROM message_attachments
      WHERE message_id IN (?)
      ORDER BY created_at ASC, id ASC
    `,
    [messageIds]
  );

  return attachMessageAttachments(normalizedMessages, attachments);
}

async function createConversationRecord({
  clientId,
  adminId,
  subject,
  status = "open",
  orderId = null,
  customRequestId = null,
}) {
  const [result] = await dbPromise.query(
    `
      INSERT INTO conversations (
        client_id,
        admin_id,
        subject,
        status,
        order_id,
        custom_request_id
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `,
    [clientId, adminId, subject, status, orderId, customRequestId]
  );

  if (customRequestId) {
    await dbPromise.query(
      "UPDATE custom_requests SET conversation_id = ? WHERE id = ? AND user_id = ?",
      [result.insertId, customRequestId, clientId]
    );
  }

  return getConversationById(result.insertId);
}

async function createConversationMessage({
  conversationId,
  senderId,
  senderRole,
  content,
  attachmentFile = null,
}) {
  const normalizedContent = typeof content === "string" ? content.trim() : "";
  const messageType = attachmentFile && attachmentFile.mimetype?.startsWith("image/")
    ? "image"
    : "text";

  if (!normalizedContent && !attachmentFile) {
    return {
      error: "Le message ne peut pas etre vide",
    };
  }

  const [result] = await dbPromise.query(
    `
      INSERT INTO messages (
        conversation_id,
        sender_id,
        sender_role,
        message,
        message_type
      )
      VALUES (?, ?, ?, ?, ?)
    `,
    [conversationId, senderId, senderRole, normalizedContent || null, messageType]
  );

  if (attachmentFile) {
    const filePath = `/uploads/messages/${attachmentFile.filename}`;
    await dbPromise.query(
      `
        INSERT INTO message_attachments (
          message_id,
          file_path,
          filename,
          mime_type,
          file_size
        )
        VALUES (?, ?, ?, ?, ?)
      `,
      [
        result.insertId,
        filePath,
        attachmentFile.originalname || attachmentFile.filename,
        attachmentFile.mimetype || "application/octet-stream",
        attachmentFile.size || null,
      ]
    );
  }

  await dbPromise.query("UPDATE conversations SET updated_at = current_timestamp() WHERE id = ?", [
    conversationId,
  ]);

  const messages = await getConversationMessages(conversationId, { id: senderId });
  return {
    message: messages.find((item) => Number(item.id) === Number(result.insertId)) || null,
  };
}

app.get("/", (req, res) => {
  res.send("Backend khdam");
});

app.get("/api/test", (req, res) => {
  res.json({ message: "Hello Ismail" });
});

app.get(
  "/api/test-db",
  asyncHandler(async (req, res) => {
    const [result] = await dbPromise.query("SELECT 1 AS test");

    res.json({
      success: true,
      message: "Connexion MySQL reussie",
      result,
    });
  })
);

app.post(
  "/api/register",
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    const [existingUsers] = await dbPromise.query("SELECT id FROM users WHERE email = ?", [email]);

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await dbPromise.query(
      "INSERT INTO users (full_name, email, password, role) VALUES (?, ?, ?, ?)",
      [name, email, hashedPassword, "client"]
    );

    res.status(201).json({
      success: true,
      message: "Registration successful",
      userId: result.insertId,
    });
  })
);

app.post(
  "/api/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    const [users] = await dbPromise.query("SELECT * FROM users WHERE email = ? LIMIT 1", [email]);

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const user = users[0];
    const storedPassword = user.password || "";
    const isHashedPassword = storedPassword.startsWith("$2");
    const isPasswordValid = isHashedPassword
      ? await bcrypt.compare(password, storedPassword)
      : password === storedPassword;

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password",
      });
    }

    const normalizedUser = normalizeUser(user);

    res.json({
      success: true,
      message: "Login successful",
      token: createAuthToken(normalizedUser),
      user: normalizedUser,
    });
  })
);

app.get(
  "/api/conversations",
  requireAuth,
  asyncHandler(async (req, res) => {
    const conversations = await getConversationsForUser(req.authUser.id);

    res.json({
      success: true,
      conversations,
    });
  })
);

app.post(
  "/api/conversations",
  requireAuth,
  asyncHandler(async (req, res) => {
    const subject = String(req.body.subject || "").trim();
    const initialMessage = String(req.body.initialMessage || "").trim();
    const customRequestId = req.body.customRequestId ? Number(req.body.customRequestId) : null;

    if (!subject) {
      return res.status(400).json({
        success: false,
        message: "Le sujet de la conversation est obligatoire",
      });
    }

    if (customRequestId) {
      const [customRequests] = await dbPromise.query(
        "SELECT id FROM custom_requests WHERE id = ? AND user_id = ? LIMIT 1",
        [customRequestId, req.authUser.id]
      );

      if (customRequests.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Demande personnalisee introuvable",
        });
      }
    }

    const adminId = await getFirstAdminUserId();
    if (!adminId) {
      return res.status(400).json({
        success: false,
        message: "Aucun administrateur disponible pour cette conversation",
      });
    }

    const conversation = await createConversationRecord({
      clientId: req.authUser.id,
      adminId,
      subject,
      customRequestId,
    });

    let createdMessage = null;
    if (initialMessage) {
      const result = await createConversationMessage({
        conversationId: conversation.id,
        senderId: req.authUser.id,
        senderRole: "client",
        content: initialMessage,
      });
      createdMessage = result.message;
    }

    const refreshedConversation = await getConversationById(conversation.id);

    res.status(201).json({
      success: true,
      conversation: refreshedConversation,
      message: createdMessage,
    });
  })
);

app.get(
  "/api/conversations/:id/messages",
  requireAuth,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.id);
    const conversation = await assertConversationAccess(conversationId, req.authUser);

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: "Conversation introuvable",
      });
    }

    if (conversation === false) {
      return res.status(403).json({
        success: false,
        message: "Acces interdit",
      });
    }

    const messages = await getConversationMessages(conversationId, req.authUser);

    res.json({
      success: true,
      conversation,
      messages,
    });
  })
);

app.post(
  "/api/conversations/:id/messages",
  requireAuth,
  messageUploadMiddleware,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.id);
    const conversation = await assertConversationAccess(conversationId, req.authUser);

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: "Conversation introuvable",
      });
    }

    if (conversation === false) {
      return res.status(403).json({
        success: false,
        message: "Acces interdit",
      });
    }

    if (normalizeConversationStatus(conversation.status) === "closed") {
      return res.status(400).json({
        success: false,
        message: "Cette conversation est fermee",
      });
    }

    const created = await createConversationMessage({
      conversationId,
      senderId: req.authUser.id,
      senderRole: "client",
      content: req.body.message,
      attachmentFile: req.file || null,
    });

    if (created.error) {
      return res.status(400).json({
        success: false,
        message: created.error,
      });
    }

    res.status(201).json({
      success: true,
      message: created.message,
    });
  })
);

app.get(
  "/api/cart",
  requireAuth,
  asyncHandler(async (req, res) => {
    const cart = await getCartByUser(req.authUser.id);

    res.json({
      success: true,
      cart,
    });
  })
);

app.post(
  "/api/cart/add",
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authUser.id;
    const productId = Number(req.body.productId);
    const requestedQuantity = Number(req.body.quantity || 1);
    const quantity = Number.isFinite(requestedQuantity) && requestedQuantity > 0 ? requestedQuantity : 1;

    if (!productId) {
      return res.status(400).json({
        success: false,
        message: "Invalid product",
      });
    }

    const [[product]] = await dbPromise.query(
      "SELECT id, stock FROM products WHERE id = ? LIMIT 1",
      [productId]
    );

    if (!product) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    const cartId = await getOrCreateCartId(userId);
    const [existingItems] = await dbPromise.query(
      "SELECT id, quantity FROM cart_items WHERE cart_id = ? AND product_id = ? LIMIT 1",
      [cartId, productId]
    );

    const currentQuantity = existingItems[0]?.quantity || 0;
    const nextQuantity = currentQuantity + quantity;

    if (product.stock !== null && Number(product.stock) < nextQuantity) {
      return res.status(400).json({
        success: false,
        message: "Stock insuffisant pour ce produit",
      });
    }

    if (existingItems.length > 0) {
      await dbPromise.query("UPDATE cart_items SET quantity = ? WHERE id = ?", [
        nextQuantity,
        existingItems[0].id,
      ]);
    } else {
      await dbPromise.query(
        "INSERT INTO cart_items (cart_id, product_id, quantity) VALUES (?, ?, ?)",
        [cartId, productId, quantity]
      );
    }

    const cart = await getCartByUser(userId);

    res.status(201).json({
      success: true,
      message: "Product added to cart",
      cart,
    });
  })
);

app.put(
  "/api/cart/items/:id",
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authUser.id;
    const itemId = Number(req.params.id);
    const quantity = Number(req.body.quantity);

    if (!itemId || !Number.isFinite(quantity) || quantity < 1) {
      return res.status(400).json({
        success: false,
        message: "Quantity must be at least 1",
      });
    }

    const [items] = await dbPromise.query(
      `
        SELECT ci.id, ci.cart_id AS cartId, ci.product_id AS productId, p.stock
        FROM cart_items ci
        INNER JOIN carts c ON c.id = ci.cart_id
        INNER JOIN products p ON p.id = ci.product_id
        WHERE ci.id = ? AND c.user_id = ?
        LIMIT 1
      `,
      [itemId, userId]
    );

    if (items.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Cart item not found",
      });
    }

    if (items[0].stock !== null && Number(items[0].stock) < quantity) {
      return res.status(400).json({
        success: false,
        message: "Stock insuffisant pour ce produit",
      });
    }

    await dbPromise.query("UPDATE cart_items SET quantity = ? WHERE id = ?", [quantity, itemId]);
    const cart = await getCartByUser(userId);

    res.json({
      success: true,
      message: "Cart updated",
      cart,
    });
  })
);

app.delete(
  "/api/cart/items/:id",
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authUser.id;
    const itemId = Number(req.params.id);

    if (!itemId) {
      return res.status(400).json({
        success: false,
        message: "Invalid cart item",
      });
    }

    const [result] = await dbPromise.query(
      `
        DELETE ci
        FROM cart_items ci
        INNER JOIN carts c ON c.id = ci.cart_id
        WHERE ci.id = ? AND c.user_id = ?
      `,
      [itemId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Cart item not found",
      });
    }

    const cart = await getCartByUser(userId);

    res.json({
      success: true,
      message: "Item removed",
      cart,
    });
  })
);

app.delete(
  "/api/cart/clear",
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authUser.id;
    const [carts] = await dbPromise.query(
      "SELECT id FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
      [userId]
    );

    if (carts.length > 0) {
      await dbPromise.query("DELETE FROM cart_items WHERE cart_id = ?", [carts[0].id]);
    }

    res.json({
      success: true,
      message: "Cart cleared",
      cart: {
        cartId: carts[0]?.id || null,
        items: [],
        summary: {
          subtotal: 0,
          total: 0,
          totalQuantity: 0,
          itemCount: 0,
        },
      },
    });
  })
);

app.post(
  "/api/checkout",
  requireAuth,
  asyncHandler(async (req, res) => {
    const userId = req.authUser.id;
    const { delivery, paymentMethod } = req.body;

    if (
      !delivery?.firstName ||
      !delivery?.lastName ||
      !delivery?.email ||
      !delivery?.phone ||
      !delivery?.address ||
      !delivery?.city
    ) {
      return res.status(400).json({
        success: false,
        message: "Informations de livraison incomplètes",
      });
    }

    if (!["livraison", "cmi"].includes(paymentMethod)) {
      return res.status(400).json({
        success: false,
        message: "Mode de paiement invalide",
      });
    }

    const connection = await dbPromise.getConnection();

    try {
      await connection.beginTransaction();

      const cart = await getCartByUser(userId, { connection });

      if (cart.items.length === 0) {
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: "Votre panier est vide",
        });
      }

      const address = JSON.stringify({
        firstName: delivery.firstName,
        lastName: delivery.lastName,
        email: delivery.email,
        phone: delivery.phone,
        address: delivery.address,
        city: delivery.city,
        postalCode: delivery.postalCode || "",
      });

      const total = Number(cart.summary.total.toFixed(2));
      const paymentStatus = paymentMethod === "livraison" ? "unpaid" : "pending";

      const [orderResult] = await connection.query(
        `
          INSERT INTO orders (
            user_id,
            order_type,
            custom_request_id,
            total,
            status,
            address,
            payment_method,
            payment_status
          )
          VALUES (?, 'catalog', NULL, ?, 'pending', ?, ?, ?)
        `,
        [userId, total, address, paymentMethod, paymentStatus]
      );

      for (const item of cart.items) {
        await connection.query(
          "INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)",
          [orderResult.insertId, item.productId, item.quantity, item.unitPrice]
        );
      }

      await connection.query("DELETE FROM cart_items WHERE cart_id = ?", [cart.cartId]);
      await connection.commit();

      res.status(201).json({
        success: true,
        message: "Commande créée avec succès",
        orderId: orderResult.insertId,
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  })
);

app.get(
  "/api/my-orders",
  requireAuth,
  asyncHandler(async (req, res) => {
    const orders = await getClientOrders(req.authUser.id);

    res.json({
      success: true,
      orders,
    });
  })
);

app.get(
  "/api/my-orders/:id",
  requireAuth,
  asyncHandler(async (req, res) => {
    const orderId = Number(req.params.id);

    if (!orderId) {
      return res.status(400).json({
        success: false,
        message: "Commande invalide",
      });
    }

    const order = await getClientOrderById(orderId, req.authUser.id);

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Commande introuvable",
      });
    }

    res.json({
      success: true,
      order,
    });
  })
);

app.post(
  "/api/custom-requests",
  requireAuth,
  customRequestUploadMiddleware,
  asyncHandler(async (req, res) => {
    const { title, description, dimensions, colors = "", budget = "", phone } = req.body;

    if (!title?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Le titre du projet est obligatoire",
      });
    }

    if (!description?.trim()) {
      return res.status(400).json({
        success: false,
        message: "La description du tapis est obligatoire",
      });
    }

    if (!dimensions?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Les dimensions souhaitées sont obligatoires",
      });
    }

    if (!phone?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Le numéro de téléphone est obligatoire",
      });
    }

    const imagePath = req.file ? `/uploads/custom-requests/${req.file.filename}` : null;

    const [result] = await dbPromise.query(
      `
        INSERT INTO custom_requests (
          user_id,
          title,
          description,
          dimensions,
          colors,
          budget,
          phone,
          image,
          image_path,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
      `,
      [
        req.authUser.id,
        title.trim(),
        description.trim(),
        dimensions.trim(),
        colors?.trim() || null,
        budget?.trim() || null,
        phone.trim(),
        imagePath,
        imagePath,
      ]
    );

    const [[createdRequest]] = await dbPromise.query(
      "SELECT * FROM custom_requests WHERE id = ? LIMIT 1",
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      message: "Votre demande a été envoyée avec succès",
      customRequest: normalizeCustomRequest(createdRequest),
    });
  })
);

app.get(
  "/api/custom-requests/my",
  requireAuth,
  asyncHandler(async (req, res) => {
    const [requests] = await dbPromise.query(
      `
        SELECT *
        FROM custom_requests
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
      `,
      [req.authUser.id]
    );

    res.json({
      success: true,
      customRequests: requests.map(normalizeCustomRequest),
    });
  })
);

app.get(
  "/api/admin/custom-requests",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [requests] = await dbPromise.query(
      `
        SELECT
          cr.*,
          u.full_name AS client_name,
          u.email AS client_email
        FROM custom_requests cr
        LEFT JOIN users u ON u.id = cr.user_id
        ORDER BY cr.created_at DESC, cr.id DESC
      `
    );

    res.json({
      success: true,
      customRequests: requests.map((request) => ({
        ...normalizeCustomRequest(request),
        client: {
          id: request.user_id,
          name: request.client_name,
          email: request.client_email,
        },
      })),
    });
  })
);

app.post(
  "/api/admin/custom-requests/:id/open-conversation",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.id);

    if (!requestId) {
      return res.status(400).json({
        success: false,
        message: "Demande personnalisée invalide",
      });
    }

    const [requests] = await dbPromise.query(
      `
        SELECT *
        FROM custom_requests
        WHERE id = ?
        LIMIT 1
      `,
      [requestId]
    );

    if (requests.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Demande personnalisée introuvable",
      });
    }

    const customRequest = requests[0];

    if (customRequest.conversation_id) {
      const conversation = await getConversationById(customRequest.conversation_id);

      return res.json({
        success: true,
        conversation,
      });
    }

    const fallbackAdminId = await getFirstAdminUserId();
    const adminId = req.authUser?.id || fallbackAdminId;

    if (!adminId) {
      return res.status(400).json({
        success: false,
        message: "Aucun administrateur disponible pour ouvrir la conversation",
      });
    }

    const conversation = await createConversationRecord({
      clientId: customRequest.user_id,
      adminId,
      subject: customRequest.title || "Demande personnalisée",
      status: "open",
      customRequestId: customRequest.id,
    });

    res.status(201).json({
      success: true,
      conversation,
    });
  })
);

app.get(
  "/api/admin/conversations",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const status = String(req.query.status || "").trim();
    const conversations = await getAdminConversations(status || null);

    res.json({
      success: true,
      conversations,
    });
  })
);

app.get(
  "/api/admin/conversations/:id/messages",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.id);
    const conversation = await assertConversationAccess(conversationId, req.authUser, {
      forAdmin: true,
    });

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: "Conversation introuvable",
      });
    }

    const messages = await getConversationMessages(conversationId, req.authUser);

    res.json({
      success: true,
      conversation,
      messages,
    });
  })
);

app.post(
  "/api/admin/conversations/:id/messages",
  requireAdmin,
  messageUploadMiddleware,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.id);
    const conversation = await assertConversationAccess(conversationId, req.authUser, {
      forAdmin: true,
    });

    if (!conversation) {
      return res.status(404).json({
        success: false,
        message: "Conversation introuvable",
      });
    }

    const created = await createConversationMessage({
      conversationId,
      senderId: req.authUser.id,
      senderRole: "admin",
      content: req.body.message,
      attachmentFile: req.file || null,
    });

    if (created.error) {
      return res.status(400).json({
        success: false,
        message: created.error,
      });
    }

    res.status(201).json({
      success: true,
      message: created.message,
    });
  })
);

app.patch(
  "/api/admin/conversations/:id/status",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const conversationId = Number(req.params.id);
    const status = String(req.body.status || "").trim().toLowerCase();

    if (!conversationId || !CONVERSATION_STATUS_VALUES.has(status)) {
      return res.status(400).json({
        success: false,
        message: "Statut de conversation invalide",
      });
    }

    const [result] = await dbPromise.query(
      "UPDATE conversations SET status = ?, updated_at = current_timestamp() WHERE id = ?",
      [status, conversationId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Conversation introuvable",
      });
    }

    const conversation = await getConversationById(conversationId);

    res.json({
      success: true,
      conversation,
    });
  })
);

app.get(
  "/api/admin/messages",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [messages] = await dbPromise.query(
      `
        SELECT
          m.id,
          m.conversation_id,
          m.message,
          m.message_type,
          m.created_at,
          u.full_name AS client_name,
          u.email AS client_email,
          c.subject,
          c.status
        FROM messages m
        INNER JOIN conversations c ON c.id = m.conversation_id
        INNER JOIN users u ON u.id = c.client_id
        ORDER BY m.created_at DESC, m.id DESC
      `
    );

    res.json({
      success: true,
      messages: messages.map(normalizeAdminMessage),
    });
  })
);

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const stats = await getDashboardStats();
    const latestOrders = await getOrders("LIMIT 5");

    res.json({
      success: true,
      stats,
      latestOrders,
    });
  })
);

app.get("/api/test-route", (req, res) => {
  res.json({ message: "Backend OK" });
});

app.get("/api/categories", async (req, res) => {
  try {
    const [categories] = await dbPromise.query(`
      SELECT id, name
      FROM categories
      ORDER BY name ASC
    `);

    res.json(categories);
  } catch (error) {
    console.error("Erreur GET /api/categories:", error);
    res.status(500).json({
      success: false,
      error: "Erreur serveur lors du chargement des catégories",
      details: error.message,
    });
  }
});

app.get(
  "/api/products",
  asyncHandler(async (req, res) => {
    const [products] = await dbPromise.query(`${PRODUCT_SELECT_FIELDS} ORDER BY p.id DESC`);

    res.json({
      success: true,
      products: products.map(normalizeProduct),
    });
  })
);

app.post(
  "/api/products",
  requireAdmin,
  productUploadMiddleware,
  asyncHandler(async (req, res) => {
    const {
      name,
      description = "",
      dimensions = "",
      price,
      stock = 0,
      categoryId = null,
      category_id = null,
    } = req.body;
    const imagePath = req.file ? `/uploads/products/${req.file.filename}` : null;
    const nextCategoryId = category_id || categoryId || null;

    if (!name || Number.isNaN(Number(price))) {
      return res.status(400).json({
        success: false,
        message: "Name and valid price are required",
      });
    }

    const [result] = await dbPromise.query(
      `
        INSERT INTO products (category_id, name, description, dimensions, price, image, stock)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [
        nextCategoryId || null,
        String(name).trim(),
        String(description || "").trim() || null,
        String(dimensions || "").trim() || null,
        Number(price),
        imagePath || null,
        Number(stock) || 0,
      ]
    );

    const [[createdProduct]] = await dbPromise.query(`${PRODUCT_SELECT_FIELDS} WHERE p.id = ?`, [
      result.insertId,
    ]);

    res.status(201).json({
      success: true,
      product: normalizeProduct(createdProduct),
    });
  })
);

app.put(
  "/api/products/:id",
  requireAdmin,
  productUploadMiddleware,
  asyncHandler(async (req, res) => {
    const productId = Number(req.params.id);
    const {
      name,
      description = "",
      dimensions = "",
      price,
      stock = 0,
      categoryId = null,
      category_id = null,
    } = req.body;
    const nextCategoryId = category_id || categoryId || null;

    if (!productId || !name || Number.isNaN(Number(price))) {
      return res.status(400).json({
        success: false,
        message: "Invalid product payload",
      });
    }

    const [existingProducts] = await dbPromise.query(
      "SELECT image FROM products WHERE id = ? LIMIT 1",
      [productId]
    );

    if (existingProducts.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Product not found",
      });
    }

    const nextImage = req.file
      ? `/uploads/products/${req.file.filename}`
      : existingProducts[0].image || null;

    const [result] = await dbPromise.query(
      `
        UPDATE products
        SET category_id = ?, name = ?, description = ?, dimensions = ?, price = ?, image = ?, stock = ?
        WHERE id = ?
      `,
      [
        nextCategoryId || null,
        String(name).trim(),
        String(description || "").trim() || null,
        String(dimensions || "").trim() || null,
        Number(price),
        nextImage,
        Number(stock) || 0,
        productId,
      ]
    );

    const [[updatedProduct]] = await dbPromise.query(`${PRODUCT_SELECT_FIELDS} WHERE p.id = ?`, [
      productId,
    ]);

    res.json({
      success: true,
      product: normalizeProduct(updatedProduct),
    });
  })
);

app.delete(
  "/api/products/:id",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const productId = Number(req.params.id);

    if (!productId) {
      return res.status(400).json({
        success: false,
        message: "Invalid product id",
      });
    }

    try {
      const [result] = await dbPromise.query("DELETE FROM products WHERE id = ?", [productId]);

      if (result.affectedRows === 0) {
        return res.status(404).json({
          success: false,
          message: "Product not found",
        });
      }

      res.json({
        success: true,
        message: "Product deleted",
      });
    } catch (error) {
      if (error.code === "ER_ROW_IS_REFERENCED_2") {
        return res.status(409).json({
          success: false,
          message: "This product is linked to existing orders",
        });
      }

      throw error;
    }
  })
);

app.get(
  "/api/orders",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const orders = await getOrders();

    res.json({
      success: true,
      orders,
    });
  })
);

app.get(
  "/api/admin/orders",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const orders = await getOrders();

    res.json({
      success: true,
      orders,
    });
  })
);

app.put(
  "/api/orders/:id/status",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const orderId = Number(req.params.id);
    const { status } = req.body;

    if (!orderId || !ADMIN_STATUS_VALUES.has(status)) {
      return res.status(400).json({
        success: false,
        message: "Invalid order status",
      });
    }

    const dbStatus = mapAdminStatusToDb(status);
    const [result] = await dbPromise.query("UPDATE orders SET status = ? WHERE id = ?", [dbStatus, orderId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });
    }

    res.json({
      success: true,
      message: "Order status updated",
    });
  })
);

app.get(
  "/api/users",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [users] = await dbPromise.query(
      `
        SELECT
          id,
          full_name AS name,
          email,
          role,
          created_at AS createdAt
        FROM users
        ORDER BY created_at DESC, id DESC
      `
    );

    res.json({
      success: true,
      users,
    });
  })
);

app.get(
  "/api/admin/users",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [users] = await dbPromise.query(
      `
        SELECT
          id,
          full_name AS name,
          email,
          role,
          created_at AS createdAt
        FROM users
        ORDER BY created_at DESC, id DESC
      `
    );

    res.json({
      success: true,
      users,
    });
  })
);

async function startServer() {
  try {
    await ensureProductSchema();
    await ensureCategorySeed();
    await ensureOrderSchema();
    await ensureCustomRequestSchema();
    await ensureConversationSchema();
    await ensureMessagesSchema();
    await ensureMessageAttachmentsSchema();

    console.log("Schema ready");
  } catch (error) {
    console.error("Schema error:", error.message);
  }
   app.post(
  "/api/admin/custom-requests/:id/open-conversation",
  requireAdmin,
  asyncHandler(async (req, res) => {
    const requestId = Number(req.params.id);

    if (!requestId) {
      return res.status(400).json({
        success: false,
        message: "Invalid custom request id",
      });
    }

    const [[customRequest]] = await dbPromise.query(
      `
        SELECT 
          cr.*,
          u.full_name AS client_name,
          u.email AS client_email
        FROM custom_requests cr
        LEFT JOIN users u ON u.id = cr.user_id
        WHERE cr.id = ?
        LIMIT 1
      `,
      [requestId]
    );

    if (!customRequest) {
      return res.status(404).json({
        success: false,
        message: "Demande personnalisée introuvable",
      });
    }

    if (customRequest.conversation_id) {
      const conversation = await getConversationById(customRequest.conversation_id);

      return res.json({
        success: true,
        conversation,
        conversationId: customRequest.conversation_id,
      });
    }

    const adminId = req.authUser?.id || (await getFirstAdminUserId());

    const conversation = await createConversationRecord({
      clientId: customRequest.user_id,
      adminId,
      subject: customRequest.title || "Demande personnalisée",
      customRequestId: requestId,
      status: "open",
    });

    res.status(201).json({
      success: true,
      conversation,
      conversationId: conversation.id,
    });
  })
);
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
