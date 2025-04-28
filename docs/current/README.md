# Novamind Backend Documentation

This directory contains the comprehensive documentation for the Novamind Digital Twin Platform backend.

## Documentation Organization

The documentation has been organized into a logical structure with numbered files indicating the recommended reading order. The structure is as follows:

- **00-series**: Introduction and organization
  - [00_Documentation_Structure.md](00_Documentation_Structure.md)
  - [00_Documentation_Index.md](00_Documentation_Index.md)

- **01-02 series**: Overview and Executive Summary
  - [01_Overview.md](01_Overview.md)
  - [02_Executive_Summary.md](02_Executive_Summary.md)

- **10-series**: Architecture
  - [10_Architecture.md](10_Architecture.md)
  - [11_API_Architecture.md](11_API_Architecture.md)
  - [12_Security_Architecture.md](12_Security_Architecture.md)
  - [13_Deployment_Architecture.md](13_Deployment_Architecture.md)

- **20-series**: Security and Compliance
  - [20_Security_and_Compliance.md](20_Security_and_Compliance.md)

- **30-series**: Domain Model
  - [30_Domain_Model.md](30_Domain_Model.md)
  - [35_Digital_Twin.md](35_Digital_Twin.md)
  - [36_Digital_Twin_Data_Model.md](36_Digital_Twin_Data_Model.md)
  - [37_Digital_Twin_API.md](37_Digital_Twin_API.md)

- **40-series**: Data Pipelines
  - [40_Data_Pipeline.md](40_Data_Pipeline.md)

- **50-series**: API Guidelines
  - [50_API_Guidelines.md](50_API_Guidelines.md)

- **60-series**: Implementation
  - [60_Implementation.md](60_Implementation.md)

- **70-series**: Infrastructure
  - [70_Infrastructure.md](70_Infrastructure.md)

- **80-series**: Testing
  - [80_Testing_Guide.md](80_Testing_Guide.md)

## Reading Paths

Different stakeholders should follow different reading paths as outlined in [00_Documentation_Structure.md](00_Documentation_Structure.md).

## Documentation Standards

- All documentation is in Markdown format
- Diagrams are included where appropriate (using PlantUML or Mermaid)
- Code examples are provided for API endpoints
- Security and privacy considerations are documented for all data flows
- Each document includes a "Last Updated" date

## Recent Documentation Updates

The documentation has been reorganized to provide a more cohesive and clear structure:

1. Removed redundant Digital Twin documentation (10_Digital_Twin.md was consolidated with 35_Digital_Twin.md)
2. Updated all cross-references between documents
3. Ensured consistent "Last Updated" dates across documentation
4. Verified that all documentation accurately reflects the current codebase structure
5. Organized documents into a logical numbering system that makes navigation intuitive

## Source of Truth

While we strive to keep this documentation up-to-date, the codebase itself is always the ultimate source of truth. When in doubt, refer to the actual code implementation.

Last Updated: 2025-04-20
