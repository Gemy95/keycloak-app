-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "companyWorkName" TEXT,
    "insuranceCompanyName" TEXT,
    "medicalInsuranceCardNumber" TEXT,
    "medicalInsuranceCardImageUrl" TEXT,
    "keycloakUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3),

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_keycloakUserId_key" ON "User"("keycloakUserId");
