SET ANSI_NULLS ON;
SET QUOTED_IDENTIFIER ON;
GO

CREATE FUNCTION [dfe_ext].[canonical_utf8_v1]
(
    @value nvarchar(max)
)
RETURNS varbinary(max)
WITH SCHEMABINDING, RETURNS NULL ON NULL INPUT
AS
BEGIN
    IF @value IS NULL
        RETURN NULL;

    DECLARE @unit_count bigint = DATALENGTH(@value) / 2;
    DECLARE @position bigint = 1;
    DECLARE @unit int;
    DECLARE @low_surrogate int;
    DECLARE @codepoint int;
    DECLARE @chunk varbinary(4);
    DECLARE @result varbinary(max) = CONVERT(varbinary(max), 0x);

    WHILE @position <= @unit_count
    BEGIN
        SET @unit = UNICODE(
            SUBSTRING(
                @value COLLATE Latin1_General_100_BIN2,
                @position,
                1
            )
        );

        IF @unit = 0
            RETURN NULL;

        IF @unit BETWEEN 55296 AND 56319
        BEGIN
            IF @position = @unit_count
                RETURN NULL;

            SET @low_surrogate = UNICODE(
                SUBSTRING(
                    @value COLLATE Latin1_General_100_BIN2,
                    @position + 1,
                    1
                )
            );

            IF @low_surrogate NOT BETWEEN 56320 AND 57343
                RETURN NULL;

            SET @codepoint =
                65536
                + ((@unit - 55296) * 1024)
                + (@low_surrogate - 56320);
            SET @position = @position + 2;
        END
        ELSE
        BEGIN
            IF @unit BETWEEN 56320 AND 57343
                RETURN NULL;

            SET @codepoint = @unit;
            SET @position = @position + 1;
        END;

        IF @codepoint <= 127
            SET @chunk = CONVERT(binary(1), @codepoint);
        ELSE IF @codepoint <= 2047
            SET @chunk =
                CONVERT(binary(1), 192 + (@codepoint / 64))
                + CONVERT(binary(1), 128 + (@codepoint % 64));
        ELSE IF @codepoint <= 65535
            SET @chunk =
                CONVERT(binary(1), 224 + (@codepoint / 4096))
                + CONVERT(binary(1), 128 + ((@codepoint / 64) % 64))
                + CONVERT(binary(1), 128 + (@codepoint % 64));
        ELSE
            SET @chunk =
                CONVERT(binary(1), 240 + (@codepoint / 262144))
                + CONVERT(binary(1), 128 + ((@codepoint / 4096) % 64))
                + CONVERT(binary(1), 128 + ((@codepoint / 64) % 64))
                + CONVERT(binary(1), 128 + (@codepoint % 64));

        SET @result = @result + @chunk;
    END;

    RETURN @result;
END;
GO
