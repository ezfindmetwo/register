-- ============================================================
-- 排程預約系統 Scheduling & Registration System
-- SQL Server 資料庫結構
-- ============================================================

USE master;
GO

-- 建立資料庫
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = N'SchedulingDB')
    CREATE DATABASE SchedulingDB
    COLLATE Chinese_Taiwan_Stroke_CI_AS;
GO

USE SchedulingDB;
GO

-- ============================================================
-- 1. Email 伺服器設定表
-- ============================================================
IF OBJECT_ID('dbo.EmailSettings', 'U') IS NULL
CREATE TABLE dbo.EmailSettings (
    Id           INT            NOT NULL IDENTITY(1,1) PRIMARY KEY,
    Host         NVARCHAR(255)  NOT NULL,
    Port         INT            NOT NULL DEFAULT 587,
    Username     NVARCHAR(255)  NOT NULL,
    [Password]   NVARCHAR(500)  NOT NULL,     -- 建議實作時加密儲存
    EnableSSL    BIT            NOT NULL DEFAULT 1,
    FromEmail    NVARCHAR(255)  NOT NULL,
    UpdatedAt    DATETIME2      NOT NULL DEFAULT SYSDATETIME(),
    UpdatedBy    NVARCHAR(255)  NULL,
    CONSTRAINT CHK_EmailPort CHECK (Port BETWEEN 1 AND 65535)
);
GO

-- ============================================================
-- 2. 活動主表
-- ============================================================
IF OBJECT_ID('dbo.Events', 'U') IS NULL
CREATE TABLE dbo.Events (
    Id                  INT           NOT NULL IDENTITY(1,1) PRIMARY KEY,
    [Name]              NVARCHAR(255) NOT NULL,
    StartDate           DATE          NOT NULL,
    EndDate             DATE          NOT NULL,
    SlotStartTime       TIME          NOT NULL,    -- 每日開始時間
    SlotEndTime         TIME          NOT NULL,    -- 每日結束時間
    SlotDurationMinutes INT           NOT NULL DEFAULT 30,
    MaxSlotsPerUser     INT           NOT NULL DEFAULT 3,
    IsOpen              BIT           NOT NULL DEFAULT 0,
    CreatedAt           DATETIME2     NOT NULL DEFAULT SYSDATETIME(),
    UpdatedAt           DATETIME2     NOT NULL DEFAULT SYSDATETIME(),
    CONSTRAINT CHK_EventDates       CHECK (EndDate >= StartDate),
    CONSTRAINT CHK_SlotTimes        CHECK (SlotEndTime > SlotStartTime),
    CONSTRAINT CHK_SlotDuration     CHECK (SlotDurationMinutes BETWEEN 5 AND 480),
    CONSTRAINT CHK_MaxSlotsPerUser  CHECK (MaxSlotsPerUser >= 1)
);
GO

-- ============================================================
-- 3. 活動開放星期設定
-- (0=星期日, 1=星期一, ..., 6=星期六)
-- ============================================================
IF OBJECT_ID('dbo.EventAllowedDays', 'U') IS NULL
CREATE TABLE dbo.EventAllowedDays (
    Id          INT      NOT NULL IDENTITY(1,1) PRIMARY KEY,
    EventId     INT      NOT NULL,
    DayOfWeek   TINYINT  NOT NULL,    -- 0~6
    CONSTRAINT FK_EventAllowedDays_Events
        FOREIGN KEY (EventId) REFERENCES dbo.Events(Id) ON DELETE CASCADE,
    CONSTRAINT UQ_EventAllowedDays
        UNIQUE (EventId, DayOfWeek),
    CONSTRAINT CHK_DayOfWeek
        CHECK (DayOfWeek BETWEEN 0 AND 6)
);
GO

-- ============================================================
-- 4. 使用者表
-- ============================================================
IF OBJECT_ID('dbo.Users', 'U') IS NULL
CREATE TABLE dbo.Users (
    Id          INT            NOT NULL IDENTITY(1,1) PRIMARY KEY,
    Email       NVARCHAR(255)  NOT NULL,
    CreatedAt   DATETIME2      NOT NULL DEFAULT SYSDATETIME(),
    LastLoginAt DATETIME2      NULL,
    CONSTRAINT UQ_Users_Email UNIQUE (Email)
);
GO

-- ============================================================
-- 5. 驗證碼表
-- ============================================================
IF OBJECT_ID('dbo.VerificationCodes', 'U') IS NULL
CREATE TABLE dbo.VerificationCodes (
    Id         INT       NOT NULL IDENTITY(1,1) PRIMARY KEY,
    UserId     INT       NOT NULL,
    Code       NCHAR(6)  NOT NULL,           -- 六位英數字驗證碼
    CreatedAt  DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
    ExpiresAt  DATETIME2 NOT NULL,           -- 預設 10 分鐘後到期
    IsUsed     BIT       NOT NULL DEFAULT 0,
    CONSTRAINT FK_VerificationCodes_Users
        FOREIGN KEY (UserId) REFERENCES dbo.Users(Id)
);
GO

-- ============================================================
-- 6. 時段預約表
-- ============================================================
IF OBJECT_ID('dbo.SlotBookings', 'U') IS NULL
CREATE TABLE dbo.SlotBookings (
    Id            INT       NOT NULL IDENTITY(1,1) PRIMARY KEY,
    EventId       INT       NOT NULL,
    UserId        INT       NOT NULL,
    BookingDate   DATE      NOT NULL,
    SlotStartTime TIME      NOT NULL,
    SlotEndTime   TIME      NOT NULL,
    CreatedAt     DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
    CONSTRAINT FK_SlotBookings_Events
        FOREIGN KEY (EventId) REFERENCES dbo.Events(Id),
    CONSTRAINT FK_SlotBookings_Users
        FOREIGN KEY (UserId) REFERENCES dbo.Users(Id),
    -- 同一活動、同一天、同一時段只能被預約一次
    CONSTRAINT UQ_SlotBooking
        UNIQUE (EventId, BookingDate, SlotStartTime)
);
GO

-- ============================================================
-- 索引 (Indexes)
-- ============================================================

-- EventAllowedDays
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_EventAllowedDays_EventId')
    CREATE INDEX IX_EventAllowedDays_EventId
        ON dbo.EventAllowedDays (EventId);
GO

-- VerificationCodes：查詢未使用碼
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VerifCodes_UserId')
    CREATE INDEX IX_VerifCodes_UserId
        ON dbo.VerificationCodes (UserId, IsUsed, ExpiresAt);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_VerifCodes_Code_Active')
    CREATE INDEX IX_VerifCodes_Code_Active
        ON dbo.VerificationCodes (Code, IsUsed)
        WHERE IsUsed = 0;
GO

-- SlotBookings：查詢某活動某日預約情況
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SlotBookings_Event_Date')
    CREATE INDEX IX_SlotBookings_Event_Date
        ON dbo.SlotBookings (EventId, BookingDate, SlotStartTime);
GO

-- SlotBookings：查詢某使用者的所有預約
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_SlotBookings_User')
    CREATE INDEX IX_SlotBookings_User
        ON dbo.SlotBookings (UserId, EventId);
GO

-- Users：Email 查詢
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_Users_Email')
    CREATE INDEX IX_Users_Email
        ON dbo.Users (Email);
GO

-- ============================================================
-- 預存程序 (Stored Procedures)
-- ============================================================

-- SP1: 取得或建立使用者，並產生驗證碼
CREATE OR ALTER PROCEDURE dbo.usp_RequestVerificationCode
    @Email      NVARCHAR(255),
    @Code       NCHAR(6),
    @ExpiresMins INT = 10,
    @UserId     INT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    BEGIN TRANSACTION;
    BEGIN TRY
        -- 取得或建立使用者
        IF NOT EXISTS (SELECT 1 FROM dbo.Users WHERE Email = @Email)
            INSERT INTO dbo.Users (Email) VALUES (@Email);

        SELECT @UserId = Id FROM dbo.Users WHERE Email = @Email;

        -- 作廢舊的未使用驗證碼
        UPDATE dbo.VerificationCodes
           SET IsUsed = 1
         WHERE UserId = @UserId AND IsUsed = 0;

        -- 建立新驗證碼
        INSERT INTO dbo.VerificationCodes (UserId, Code, ExpiresAt)
        VALUES (@UserId, @Code, DATEADD(MINUTE, @ExpiresMins, SYSDATETIME()));

        COMMIT;
    END TRY
    BEGIN CATCH
        ROLLBACK;
        THROW;
    END CATCH
END;
GO

-- SP2: 驗證碼驗證
CREATE OR ALTER PROCEDURE dbo.usp_VerifyCode
    @Email   NVARCHAR(255),
    @Code    NCHAR(6),
    @IsValid BIT OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @UserId INT;
    SELECT @UserId = Id FROM dbo.Users WHERE Email = @Email;

    IF @UserId IS NULL BEGIN SET @IsValid = 0; RETURN; END

    IF EXISTS (
        SELECT 1 FROM dbo.VerificationCodes
         WHERE UserId   = @UserId
           AND Code     = @Code
           AND IsUsed   = 0
           AND ExpiresAt > SYSDATETIME()
    )
    BEGIN
        UPDATE dbo.VerificationCodes
           SET IsUsed = 1
         WHERE UserId = @UserId AND Code = @Code AND IsUsed = 0;

        UPDATE dbo.Users SET LastLoginAt = SYSDATETIME() WHERE Id = @UserId;
        SET @IsValid = 1;
    END
    ELSE
        SET @IsValid = 0;
END;
GO

-- SP3: 預約時段（含上限檢查）
CREATE OR ALTER PROCEDURE dbo.usp_BookSlot
    @EventId       INT,
    @Email         NVARCHAR(255),
    @BookingDate   DATE,
    @SlotStartTime TIME,
    @SlotEndTime   TIME,
    @ResultCode    INT OUTPUT,   -- 0=成功,1=超過上限,2=時段已滿,3=活動未開放
    @ResultMsg     NVARCHAR(255) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @UserId INT, @MaxSlots INT, @CurrentCount INT, @IsOpen BIT;

    SELECT @UserId = Id FROM dbo.Users WHERE Email = @Email;
    SELECT @MaxSlots = MaxSlotsPerUser, @IsOpen = IsOpen
      FROM dbo.Events WHERE Id = @EventId;

    IF @IsOpen = 0 BEGIN SET @ResultCode = 3; SET @ResultMsg = N'活動報名未開放'; RETURN; END

    SELECT @CurrentCount = COUNT(*) FROM dbo.SlotBookings
     WHERE EventId = @EventId AND UserId = @UserId;

    IF @CurrentCount >= @MaxSlots BEGIN
        SET @ResultCode = 1;
        SET @ResultMsg = CONCAT(N'已達選取上限 (', @MaxSlots, N' 個)');
        RETURN;
    END

    IF EXISTS (SELECT 1 FROM dbo.SlotBookings
               WHERE EventId = @EventId AND BookingDate = @BookingDate AND SlotStartTime = @SlotStartTime)
    BEGIN
        SET @ResultCode = 2; SET @ResultMsg = N'該時段已被他人預約'; RETURN;
    END

    INSERT INTO dbo.SlotBookings (EventId, UserId, BookingDate, SlotStartTime, SlotEndTime)
    VALUES (@EventId, @UserId, @BookingDate, @SlotStartTime, @SlotEndTime);

    SET @ResultCode = 0; SET @ResultMsg = N'預約成功';
END;
GO

-- SP4: 取消預約
CREATE OR ALTER PROCEDURE dbo.usp_CancelSlot
    @EventId       INT,
    @Email         NVARCHAR(255),
    @BookingDate   DATE,
    @SlotStartTime TIME
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @UserId INT;
    SELECT @UserId = Id FROM dbo.Users WHERE Email = @Email;

    DELETE FROM dbo.SlotBookings
     WHERE EventId = @EventId AND UserId = @UserId
       AND BookingDate = @BookingDate AND SlotStartTime = @SlotStartTime;
END;
GO

-- SP5: 查詢某活動某週預約狀況（含誰預約）
CREATE OR ALTER PROCEDURE dbo.usp_GetWeekBookings
    @EventId    INT,
    @WeekStart  DATE,
    @WeekEnd    DATE,
    @Email      NVARCHAR(255) = NULL   -- 若傳入，標示哪些是自己的
AS
BEGIN
    SET NOCOUNT ON;
    SELECT
        b.BookingDate,
        b.SlotStartTime,
        b.SlotEndTime,
        u.Email,
        CASE WHEN u.Email = @Email THEN 1 ELSE 0 END AS IsMine
    FROM dbo.SlotBookings b
    JOIN dbo.Users u ON b.UserId = u.Id
    WHERE b.EventId = @EventId
      AND b.BookingDate BETWEEN @WeekStart AND @WeekEnd
    ORDER BY b.BookingDate, b.SlotStartTime;
END;
GO

-- ============================================================
-- 範例初始資料
-- ============================================================

-- Email 設定範例
INSERT INTO dbo.EmailSettings (Host, Port, Username, [Password], EnableSSL, FromEmail, UpdatedBy)
VALUES (N'smtp.gmail.com', 587, N'admin@example.com', N'**encrypted**', 1, N'noreply@example.com', N'admin');

-- 活動範例
DECLARE @EventId INT;
INSERT INTO dbo.Events ([Name], StartDate, EndDate, SlotStartTime, SlotEndTime, SlotDurationMinutes, MaxSlotsPerUser, IsOpen)
VALUES (N'2025年健康檢查預約', '2025-06-01', '2025-06-30', '09:00', '17:00', 30, 3, 0);
SET @EventId = SCOPE_IDENTITY();

-- 開放週一~週五 (1~5)
INSERT INTO dbo.EventAllowedDays (EventId, DayOfWeek)
SELECT @EventId, v.d
FROM (VALUES(1),(2),(3),(4),(5)) AS v(d);

PRINT N'資料庫建立完成！';
GO
