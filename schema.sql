CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  role VARCHAR(30) NOT NULL CHECK (role IN ('customer','shopkeeper','delivery','admin')),
  name VARCHAR(120) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  phone VARCHAR(20),
  password_hash TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS shops (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID REFERENCES users(id),
  shop_name VARCHAR(160) NOT NULL,
  category VARCHAR(50) NOT NULL,
  gst_number VARCHAR(40),
  pan_number VARCHAR(30),
  address TEXT,
  latitude NUMERIC(10,7),
  longitude NUMERIC(10,7),
  opening_time TIME,
  closing_time TIME,
  status VARCHAR(30) NOT NULL DEFAULT 'pending',
  documents JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  shop_id UUID NOT NULL REFERENCES shops(id) ON DELETE CASCADE,
  name VARCHAR(200) NOT NULL,
  description TEXT,
  category VARCHAR(100),
  price NUMERIC(12,2) NOT NULL CHECK(price >= 0),
  stock INT NOT NULL DEFAULT 0,
  prescription_required BOOLEAN NOT NULL DEFAULT FALSE,
  images JSONB NOT NULL DEFAULT '[]'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id UUID NOT NULL REFERENCES users(id),
  shop_id UUID NOT NULL REFERENCES shops(id),
  delivery_partner_id UUID REFERENCES users(id),
  status VARCHAR(40) NOT NULL DEFAULT 'pending',
  subtotal NUMERIC(12,2) NOT NULL,
  delivery_fee NUMERIC(12,2) NOT NULL DEFAULT 30,
  shop_commission NUMERIC(12,2) NOT NULL DEFAULT 0,
  total NUMERIC(12,2) NOT NULL,
  cancel_until TIMESTAMPTZ NOT NULL,
  cancellation_status VARCHAR(30),
  payment_status VARCHAR(30) NOT NULL DEFAULT 'pending',
  cashfree_order_id VARCHAR(100),
  payment_session_id TEXT,
  delivery_otp_hash TEXT,
  pickup_otp_hash TEXT,
  address JSONB NOT NULL DEFAULT '{}'::jsonb,
  prescription_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS order_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  product_id UUID NOT NULL REFERENCES products(id),
  quantity INT NOT NULL CHECK(quantity > 0),
  unit_price NUMERIC(12,2) NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_locations (
  id BIGSERIAL PRIMARY KEY,
  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  delivery_partner_id UUID NOT NULL REFERENCES users(id),
  latitude NUMERIC(10,7) NOT NULL,
  longitude NUMERIC(10,7) NOT NULL,
  accuracy NUMERIC(10,2),
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS financial_ledger (
  id BIGSERIAL PRIMARY KEY,
  order_id UUID REFERENCES orders(id),
  owner_type VARCHAR(30) NOT NULL,
  owner_id UUID,
  entry_type VARCHAR(30) NOT NULL,
  amount NUMERIC(12,2) NOT NULL,
  available_at TIMESTAMPTZ NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
  provider VARCHAR(30) NOT NULL DEFAULT 'cashfree',
  provider_order_id VARCHAR(120),
  amount NUMERIC(12,2) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'created',
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS otp_codes (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  purpose VARCHAR(30) NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_id UUID,
  action VARCHAR(120) NOT NULL,
  entity_type VARCHAR(50),
  entity_id UUID,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_shop ON orders(shop_id);
CREATE INDEX IF NOT EXISTS idx_orders_delivery ON orders(delivery_partner_id);
CREATE INDEX IF NOT EXISTS idx_locations_order_time ON delivery_locations(order_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_ledger_available ON financial_ledger(status, available_at);


CREATE TABLE IF NOT EXISTS push_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  platform VARCHAR(20),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_push_tokens_user_id ON push_tokens(user_id);


CREATE TABLE IF NOT EXISTS notification_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(200) NOT NULL,
  body TEXT NOT NULL,
  type VARCHAR(60) NOT NULL,
  data JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notification_logs_user ON notification_logs(user_id, created_at DESC);
