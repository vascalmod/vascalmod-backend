-- Run this in Supabase SQL Editor to add missing columns
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS features TEXT;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS remaining_seconds BIGINT DEFAULT NULL;
