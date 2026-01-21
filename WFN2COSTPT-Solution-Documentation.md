# WFN2COSTPT Solution Documentation

## Overview

**WFN2COSTPT** (Workforce Now to CostPoint) is a .NET 8.0 integration solution that synchronizes employee data from **ADP Workforce Now (WFN)** to **Deltek CostPoint** ERP system. The application runs as an Azure WebJob, processing employee change notifications and transforming them into CostPoint-compatible import records.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Solution Structure](#solution-structure)
3. [Core Components](#core-components)
4. [Data Flow](#data-flow)
5. [Configuration System](#configuration-system)
6. [Supported Events](#supported-events)
7. [Output Modes](#output-modes)
8. [Extensibility Points](#extensibility-points)
9. [External Dependencies](#external-dependencies)
10. [Database Schema](#database-schema)
11. [Error Handling](#error-handling)
12. [Deployment](#deployment)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              WFN2COSTPT                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │   ADP WFN    │───▶│   Callisto   │───▶│   Process    │───▶│  Deltek   │ │
│  │  (Source)    │    │   Platform   │    │   Engine     │    │ CostPoint │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────────┘ │
│                             │                   │                           │
│                             ▼                   ▼                           │
│                      ┌─────────────┐    ┌─────────────┐                     │
│                      │   MySQL     │    │   Azure     │                     │
│                      │  Database   │    │   Storage   │                     │
│                      └─────────────┘    └─────────────┘                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Integration Points

| System | Purpose |
|--------|---------|
| **ADP Workforce Now** | Source HR system providing employee data and change events |
| **Callisto Platform** | Middleware platform for worker data retrieval and event notifications |
| **Deltek CostPoint** | Target ERP system receiving employee import records |
| **Azure Key Vault** | Secure storage for secrets, certificates, and connection strings |
| **Azure Blob Storage** | Output file storage for audit logs and CSV exports |
| **MySQL Database** | Client configuration and race/ethnicity mapping data |

---

## Solution Structure

```
WFN2COSTPT/
├── Program.cs                          # Application entry point
├── Process.cs                          # Main processing logic
├── ConfigurationMgrHelper.cs           # Configuration retrieval service
├── RaceEnthnicityTbl.cs               # Race/ethnicity mapping service
│
├── Constants/
│   └── ConfigurationKeys.cs            # Configuration key constants
│
├── Exceptions/
│   └── DeltekCPException.cs           # Custom exception for CostPoint errors
│
├── FilterFactory/
│   ├── Filter.cs                       # Base filter class
│   ├── FilterFactory.cs               # Filter factory
│   ├── DefaultFilter.cs               # Default filter implementation
│   └── EmmesFilter.cs                 # Emmes-specific filter
│
├── Models/
│   ├── ClientConfiguration.cs          # Client configuration model
│   ├── OutputRecord1.cs               # Primary output record
│   ├── OutputRecord2.cs               # Secondary output record
│   ├── EmplInfoRec1_2_Import.cs       # CostPoint import data structures
│   └── MethodResponse.cs              # API response model
│
├── Services/
│   ├── DeltekCPApiService.cs          # CostPoint API client
│   ├── DeltekCPTokenService.cs        # JWT token generation
│   └── DeltekCPEmplTransformService.cs # Data transformation service
│
├── TransformExtensionFactory/
│   ├── TransformExtensions.cs         # Base transform extensions
│   ├── TransformExtensionFactory.cs   # Transform factory
│   ├── DefaultTransformExtensions.cs  # Default implementations
│   └── Core4ceTransformExtensions.cs  # Core4ce-specific transforms
│
├── ConfigData/
│   └── Core4ceConfig.json             # Client-specific configuration
│
├── DBScripts/
│   └── CostPointRaceEthnicity.sql     # Database schema script
│
└── appsettings.json                    # Application settings
```

---

## Core Components

### 1. Program.cs - Application Entry Point

The application uses Microsoft's Generic Host pattern with dependency injection:

```csharp
// Key services registered:
- IWorkers                  // Callisto worker data service
- IEventNotificationsDAL    // Event notifications data access
- IAzureVaultHelper         // Azure Key Vault access
- IRaceEnthnicityTbl        // Race/ethnicity mapping
- IDeltekCPApiService       // CostPoint API client
- IDeltekCPTokenService     // Token generation
- IConfigurationMgrHelper   // Configuration management
```

**Startup Flow:**
1. Load `appsettings.json` configuration
2. Configure dependency injection container
3. Add Azure WebJobs storage services
4. Create service scope and run `Process.RunAsync()`

### 2. Process.cs - Main Processing Engine

The `Process` class orchestrates the entire data synchronization workflow.

**Key Methods:**

| Method | Description |
|--------|-------------|
| `RunAsync()` | Main entry point - initializes resources and calls ProcessChanges() |
| `ProcessChanges()` | Retrieves notifications and processes each one |
| `BuildOutput()` | Transforms worker data into output records |
| `SendToDeltek()` | Sends transformed data to CostPoint API |
| `GetWorkerData()` | Retrieves worker and work assignment data |

**Processing Workflow:**

```
1. Initialize Resources
   ├── Get Azure Storage connection string
   ├── Load client configuration
   └── Load race/ethnicity mapping data

2. Process Notifications
   ├── Retrieve pending notifications
   ├── For each notification:
   │   ├── Get worker data
   │   ├── Apply filter (qualification check)
   │   ├── Build output records
   │   ├── Send to CostPoint (API) or Write CSV (File)
   │   └── Mark notification as processed

3. Finalize
   ├── Upload audit log to Azure Storage
   ├── Upload output file (if CSV mode)
   └── Log statistics
```

### 3. Services Layer

#### DeltekCPApiService

Handles HTTP communication with the CostPoint REST API:

- Authenticates using JWT token (Basic authentication header)
- Posts employee import data as JSON
- Parses response and throws `DeltekCPException` on errors

#### DeltekCPTokenService

Generates JWT tokens for CostPoint authentication:

1. Retrieves X.509 certificate from Azure Key Vault
2. Creates JWT header (RS256 algorithm)
3. Creates payload with `exp`, `iat`, `nbf`, `sub` claims
4. Signs with RSA private key
5. Returns Base64-encoded token

#### DeltekCPEmplTransformService

Transforms internal output records to CostPoint import format:

- Maps `OutputRecord1` and `OutputRecord2` to `EMPLINFOREC1_2_IMPORT_ROOT`
- Handles employee data, labor information, and phone records
- Applies client-specific transform extensions

---

## Data Flow

### Input Data Model

Data flows from ADP Workforce Now through the Callisto platform:

```
Worker (from Callisto.Data)
├── Person
│   ├── LegalName (GivenName, FamilyName1, MiddleName)
│   ├── LegalAddress
│   ├── GovernmentIDs (SSN)
│   ├── BirthDate
│   ├── GenderCode
│   ├── MaritalStatusCode
│   ├── EthnicityCode
│   └── Communication (Mobiles, Landlines)
├── WorkerStatus
├── WorkerDates (HireDate, RehireDate, TerminationDate)
├── BusinessCommunication (Emails)
└── CustomFieldGroup

Workassignment
├── PositionID
├── HireDate
├── HomeWorkLocation
├── HomeOrganizationalUnits
├── BaseRemuneration (HourlyRateAmount, PayPeriodRateAmount)
├── WageLawCoverage
├── WorkerTypeCode
├── JobCode
├── OccupationalClassifications
├── ReportsTo
├── BargainingUnit
└── LaborUnion
```

### Output Data Model

Two output records are generated for each employee:

**OutputRecord1 (Primary Employee Data):**
- Personal information (Name, SSN, DOB, Gender)
- Employment details (Status, Hire Date, Employee Type)
- Compensation (Rate, Rate Type, FLSA Exempt)
- Organization (Home Org, Labor Category, Labor Location)
- Address information
- Contact information

**OutputRecord2 (Extended Employee Data):**
- Taxable entity
- Adjusted hire date / Termination date
- Supervisor information
- Work email
- Job title
- Labor group
- Security organization

### CostPoint Import Structure

```
EMPLINFOREC1_2_IMPORT_ROOT
└── document (EMPLINFOREC1_2_IMPORT)
    └── rows[]
        └── row (LDMEINFO_EMPL)
            ├── data (Employee master data)
            └── children[]
                ├── LDM_EMPLLABINFO_CHILD (Labor information)
                └── LDMEINFO_EMPLPHONE (Phone records)
```

---

## Configuration System

### Application Settings (appsettings.json)

```json
{
  "ClientId": "56914591-668b-40b7-a5b5-f3d81eea0555",
  "Host": "https://adpmarketplaceconnector.azurewebsites.net",
  "CallistoVaultServiceHost": "https://callisto-vault-service.azurewebsites.net",
  "ConfigurationMgrServiceHost": "https://callisto-configurationmgr-service.azurewebsites.net",
  "CallistoClientDBConnStrKey": "callisto-mysql-client-connstr",
  "AzureWebJobsStorageKey": "azure-webjobs-storage-connstr",
  "DeltekCPUserNameKey": "deltek-cp-core4ce-username",
  "DeltekCPCertNameKey": "deltek-cp-core4ce-certname",
  "DeltekCPUri": "https://cp-core4ce.prd.mydeltekgcc.com/cpweb/cprestfulws/..."
}
```

### Client Configuration (from Configuration Manager Service)

| Key | Description | Example Values |
|-----|-------------|----------------|
| `PROCESSING_COCODE` | Client processing code | `CP_Core4ce`, `CP_Emmes` |
| `OUTPUT_STORAGE_CONTAINER_NM` | Azure blob container name | `output` |
| `EEID_TYPE` | Employee ID format | `3`, `4`, `5`, `6`, or blank |
| `HOME_ORG` | Home organization source | `BU`, `DPT`, `CTR` |
| `DEFAULT_LABOR_CATEGORY` | Default labor category | `ADMIN`, `TECH` |
| `LABOR_GROUP` | Labor group source | `LU`, `#Locator Code` |
| `LABOR_INPUT` | Locator input source | `BU`, `#Locator Code` |
| `LOCATION` | Location source | `HWLSC`, `HWLC`, `NA` |
| `CYCLE` | Timesheet/leave cycle | `W`, `BW`, `SM`, `M` |
| `NAICS` | Workers comp code source | `NAICS` or specific code |
| `DEFAULT_OT_STATE` | OT state source | `HWLSC`, `HWLC`, state code |
| `EE_CLASS` | Employee class source | Field name or value |
| `CAPS_IND` | Uppercase names | `Yes`, `No` |
| `HOME_TELE` | Phone source | `M` (mobile), `L` (landline) |
| `BYPASS_ACTIVE` | Skip inactive status | `Y`, `N` |
| `SSN_OVERRIDE` | Override SSN value | Value or blank |
| `DATE_OF_BIRTH` | Override DOB | Value or blank |
| `MARITAL_STATUS_OVERRIDE` | Override marital status | Value or blank |
| `GENDER_OVERRIDE` | Override gender | Value or blank |
| `EMPLOYEE_ADDRESS_OVERRIDE` | Skip address output | `NA` to skip |
| `YEARLY_WORK_HOURS` | Yearly hours | `R` (calculate), `2080`, etc. |
| `SEND_RACE_ETHNICITY` | Include race/ethnicity | `Y`, `N` |
| `SEND_JOB_TITLE` | Job title source | `JC` (code), `JN` (name) |
| `API_OUTPUT` | Output mode | `Y` (API), `N` (CSV) |
| `MANAGER_ID` | Manager ID source | Field name with `#` prefix |
| `SUPERVISOR_NAME` | Include supervisor name | `RTN` to include |

---

## Supported Events

The application processes the following ADP Workforce Now events:

| Event Code | Description |
|------------|-------------|
| `worker.hire` | New employee hire |
| `worker.rehire` | Employee rehire |
| `worker.terminate` | Employee termination |
| `worker.on-leave` | Employee on leave (LOA, FML) |
| `worker.legal-name.change` | Name change |
| `worker.legal-address.change` | Address change |
| `worker.legal-address.add` | New address |
| `worker.gender.change` | Gender change |
| `worker.marital-status.change` | Marital status change |
| `worker.work-assignment.modify` | Work assignment modification |
| `worker.work-assignment.base-remuneration.change` | Compensation change |
| `worker.work-assignment.home-organizational-units.modify` | Org unit change |
| `worker.work-assignment.home-work-location.change` | Work location change |
| `worker.reports-to.modify` | Reporting structure change |
| `worker.business-communication.email.change` | Email change |
| `worker.business-communication.email.add` | New email |
| `worker.custom-field.string.change` | Custom string field change |
| `worker.custom-field.code.change` | Custom code field change |

---

## Output Modes

### API Output Mode (APIOutput = "Y")

Data is sent directly to the CostPoint REST API:

1. Transform records to `EMPLINFOREC1_2_IMPORT_ROOT` JSON
2. Generate JWT authentication token
3. POST to CostPoint import endpoint
4. Parse response and handle errors
5. Log success/failure to audit file

### CSV Output Mode (APIOutput = "N")

Data is written to CSV files:

1. Transform records to CSV format using `CSVWriter`
2. Write to memory stream
3. Upload to Azure Blob Storage
4. File naming: `{ProcessingCoCode}.txt`

---

## Extensibility Points

### Filter Factory

Allows client-specific filtering of notifications before processing:

```csharp
// FilterFactory.cs
public static Filter GetFilter(string companyID)
{
    return companyID switch
    {
        "CP_Emmes" => new EmmesFilter(),
        _ => new Filter()  // Default: process all
    };
}
```

**Current Implementations:**

| Filter | Logic |
|--------|-------|
| `Filter` (default) | Always returns `true` - processes all notifications |
| `EmmesFilter` | Only processes workers in specific business units |

**Adding a New Filter:**
1. Create class extending `Filter`
2. Override `Qualified(Worker, Workassignment, EventNotification)` method
3. Register in `FilterFactory.GetFilter()` switch statement

### Transform Extension Factory

Allows client-specific data transformations:

```csharp
// TransformExtensionFactory.cs
public static TransformExtensions Get(string companyID)
{
    return companyID switch
    {
        "CP_Core4ce" => new Core4ceTransformExtensions(),
        _ => new TransformExtensions()  // Default
    };
}
```

**Extension Methods:**

| Method | Purpose |
|--------|---------|
| `GetRef1Id(OutputRecord2)` | Returns Reference 1 ID value |
| `GetSalRecLabLocCd(OutputRecord1)` | Returns Salary Record Labor Location Code |

**Current Implementations:**

| Extension | Logic |
|-----------|-------|
| `TransformExtensions` (default) | Returns `null` for both methods |
| `Core4ceTransformExtensions` | Special logic for LBT.Customer Site / LBT.Company1 Site |

---

## External Dependencies

### NuGet Packages

| Package | Version | Purpose |
|---------|---------|---------|
| `Callisto.Data` | 3.0.6 | Data access layer (workers, notifications) |
| `Callisto.Models` | 1.0.0 | Shared data models |
| `Microsoft.Extensions.Hosting` | 8.0.0 | Generic host framework |
| `Microsoft.AspNetCore.WebUtilities` | 8.0.1 | Web utilities |
| `System.IdentityModel.Tokens.Jwt` | 7.2.0 | JWT token handling |

### Callisto Platform Services

| Service | Description |
|---------|-------------|
| `IWorkers` | Retrieves worker data from ADP via Callisto |
| `IEventNotificationsDAL` | Manages event notifications |
| `IAzureVaultHelper` | Azure Key Vault access |
| `HttpHelper` | HTTP client utilities |
| `AzureStorageHelper` | Azure Blob Storage utilities |
| `CSVWriter` | CSV serialization |
| `Json` | JSON serialization/deserialization |

---

## Database Schema

### Race/Ethnicity Mapping Table

```sql
CREATE TABLE `costpt_race_ethnicity` (
  `record_id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` varchar(50) NOT NULL,
  `wfn_ethnicity_code` varchar(1) DEFAULT NULL,
  `wfn_race_code` varchar(1) DEFAULT NULL,
  `costpt_race_ethnicity_code` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`record_id`),
  KEY `client_id` (`client_id`)
);
```

**Purpose:** Maps ADP Workforce Now ethnicity/race codes to CostPoint race/ethnicity codes.

**Example Mappings:**

| WFN Ethnicity | WFN Race | CostPoint Code |
|---------------|----------|----------------|
| 4 | 1 | WHITE |
| 4 | 4 | ASIAN |
| 3 | 3 | OTHER_HISP |
| 4 | 2 | BLACK_WHT |
| 4 | 9 | OTHER |
| 4 | 6 | NH_PI |

---

## Error Handling

### Exception Types

| Exception | Description |
|-----------|-------------|
| `DeltekCPException` | CostPoint API errors (authentication, validation, import failures) |
| `IntegrationException` | Callisto platform integration errors |
| `Exception` | General system errors |

### Error Logging

1. **Audit File:** Individual record successes/failures logged
2. **Abend File:** Critical errors uploaded to `abends` container
3. **Console Logging:** Real-time logging via Microsoft.Extensions.Logging

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error occurred during processing |

---

## Deployment

### Azure WebJob Configuration

**Settings.job:**
```json
{
  "schedule": "0 0 * * * *"  // Runs hourly
}
```

### Required Azure Resources

1. **Azure WebJob** - Application host
2. **Azure Key Vault** - Secrets and certificates
3. **Azure Blob Storage** - Output files and logs
4. **Azure MySQL** - Client configuration data

### Required Secrets (Azure Key Vault)

| Secret Name | Description |
|-------------|-------------|
| `callisto-mysql-client-connstr` | MySQL connection string |
| `azure-webjobs-storage-connstr` | Azure Storage connection string |
| `deltek-cp-{client}-username` | CostPoint API username |
| `deltek-cp-{client}-certname` | CostPoint certificate name |

### Required Certificates (Azure Key Vault)

| Certificate | Description |
|-------------|-------------|
| Deltek CostPoint certificate | X.509 certificate for JWT signing |

---

## Version History

| Version | Changes |
|---------|---------|
| v3.0.6 | Latest - Race/ethnicity table moved to database |
| v3.0.5 | Previous stable release |
| v2.0.x | Version 2 enhancements |
| v1.0.x | Initial releases |

---

## Support

For issues related to this integration:

1. Check Azure WebJob logs for error details
2. Review audit files in Azure Blob Storage
3. Verify configuration in Configuration Manager
4. Check Callisto platform connectivity
5. Verify CostPoint API endpoint availability
