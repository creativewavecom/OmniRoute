/**
 * User Service
 * 
 * Handles user CRUD, authentication, and lifecycle.
 */

import { v4 as uuidv4 } from "uuid";
import { getDbInstance } from "./core";
import { backupDbFile } from "./backup";
import bcrypt from "bcryptjs";

interface User {
  id: string;
  email: string;
  password_hash: string;
  name?: string | null;
  status: "active" | "suspended" | "deleted";
  created_at: string;
  updated_at: string;
  deleted_at?: string | null;
}

/**
 * Create a new user
 */
export async function createUser(
  email: string,
  password: string,
  name?: string
): Promise<User | null> {
  if (!email || !password) {
    throw new Error("Email and password are required");
  }

  // Hash password (bcrypt: 10 rounds)
  const password_hash = await bcrypt.hash(password, 10);
  const now = new Date().toISOString();

  try {
    const db = getDbInstance();
    const id = uuidv4();

    db.prepare(
      `INSERT INTO users (id, email, password_hash, name, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(id, email, password_hash, name || null, "active", now, now);

    backupDbFile("pre-write");

    return {
      id,
      email,
      password_hash,
      name: name || null,
      status: "active",
      created_at: now,
      updated_at: now,
    } as User;
  } catch (err) {
    if (String(err).includes("UNIQUE constraint failed")) {
      throw new Error("Email already exists");
    }
    throw err;
  }
}

/**
 * Get user by ID
 */
export async function getUserById(userId: string): Promise<User | null> {
  if (!userId) return null;

  try {
    const db = getDbInstance();
    const row = db
      .prepare<User>(`SELECT * FROM users WHERE id = ?`)
      .get(userId);
    return row || null;
  } catch (err) {
    console.error(`[UserService] getUserById failed: ${String(err)}`);
    return null;
  }
}

/**
 * Get user by email (for login)
 */
export async function getUserByEmail(email: string): Promise<User | null> {
  if (!email) return null;

  try {
    const db = getDbInstance();
    const row = db
      .prepare<User>(
        `SELECT * FROM users WHERE email = ? AND deleted_at IS NULL`
      )
      .get(email);
    return row || null;
  } catch (err) {
    console.error(`[UserService] getUserByEmail failed: ${String(err)}`);
    return null;
  }
}

/**
 * Verify password
 */
export async function verifyPassword(
  password: string,
  passwordHash: string
): Promise<boolean> {
  try {
    return await bcrypt.compare(password, passwordHash);
  } catch (err) {
    console.error(`[UserService] Password verification failed: ${String(err)}`);
    return false;
  }
}

/**
 * Update user
 */
export async function updateUser(
  userId: string,
  updates: Partial<Omit<User, "id" | "created_at">>
): Promise<User | null> {
  if (!userId) return null;

  try {
    const db = getDbInstance();
    const now = new Date().toISOString();

    const fields: string[] = [];
    const values: unknown[] = [];

    if (updates.email !== undefined) {
      fields.push("email = ?");
      values.push(updates.email);
    }
    if (updates.name !== undefined) {
      fields.push("name = ?");
      values.push(updates.name);
    }
    if (updates.status !== undefined) {
      fields.push("status = ?");
      values.push(updates.status);
    }
    if (updates.password_hash !== undefined) {
      fields.push("password_hash = ?");
      values.push(updates.password_hash);
    }

    fields.push("updated_at = ?");
    values.push(now);
    values.push(userId);

    db.prepare(
      `UPDATE users SET ${fields.join(", ")} WHERE id = ?`
    ).run(...values);

    backupDbFile("pre-write");
    return getUserById(userId);
  } catch (err) {
    console.error(`[UserService] updateUser failed: ${String(err)}`);
    return null;
  }
}

/**
 * Delete user (soft delete)
 */
export async function deleteUser(userId: string): Promise<boolean> {
  if (!userId) return false;

  try {
    const db = getDbInstance();
    const now = new Date().toISOString();

    db.prepare(
      `UPDATE users SET status = ?, deleted_at = ?, updated_at = ? WHERE id = ?`
    ).run("deleted", now, now, userId);

    backupDbFile("pre-write");
    return true;
  } catch (err) {
    console.error(`[UserService] deleteUser failed: ${String(err)}`);
    return false;
  }
}
