/*
  Warnings:

  - You are about to drop the `Connection` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Execution` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Node` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `Workflow` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "Connection" DROP CONSTRAINT "Connection_workflowId_fkey";

-- DropForeignKey
ALTER TABLE "Execution" DROP CONSTRAINT "Execution_workflowId_fkey";

-- DropForeignKey
ALTER TABLE "Node" DROP CONSTRAINT "Node_workflowId_fkey";

-- DropForeignKey
ALTER TABLE "Workflow" DROP CONSTRAINT "Workflow_userId_fkey";

-- DropTable
DROP TABLE "Connection";

-- DropTable
DROP TABLE "Execution";

-- DropTable
DROP TABLE "Node";

-- DropTable
DROP TABLE "Workflow";

-- CreateTable
CREATE TABLE "ChatSession" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "endedAt" TIMESTAMP(3),
    "moodSummary" TEXT,
    "emotionScore" JSONB,
    "reportStatus" TEXT NOT NULL DEFAULT 'pending',

    CONSTRAINT "ChatSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reports" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "summary" TEXT NOT NULL,
    "insights" JSONB NOT NULL,
    "suggestions" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "generated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "behavioral_insights" JSONB,
    "recommendations" JSONB,
    "progress_metrics" JSONB,
    "report_data" JSONB,

    CONSTRAINT "reports_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "reports_sessionId_key" ON "reports"("sessionId");

-- AddForeignKey
ALTER TABLE "ChatSession" ADD CONSTRAINT "ChatSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "ChatSession"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
