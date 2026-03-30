/*
  Warnings:

  - The values [INTELLIGENCE,BUSINESS_IMPACT] on the enum `ScanCategory` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "ScanCategory_new" AS ENUM ('TLS', 'HEADERS', 'NETWORK', 'EMAIL');
ALTER TABLE "ScanResult" ALTER COLUMN "category" TYPE "ScanCategory_new" USING ("category"::text::"ScanCategory_new");
ALTER TYPE "ScanCategory" RENAME TO "ScanCategory_old";
ALTER TYPE "ScanCategory_new" RENAME TO "ScanCategory";
DROP TYPE "public"."ScanCategory_old";
COMMIT;

-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "businessImpactData" JSONB,
ADD COLUMN     "intelligenceData" JSONB;
