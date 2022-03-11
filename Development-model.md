The purpose of this document is to define a procedure to carry out the analysis, design, implementation, and validation of development tasks that involve important changes in the product and the user experience.

## Procedure

### 1. Requirement analysis
|DRI|Team leaders|
|---|---|

Given a product need, functional and non-functional requirements are defined. Discuss task dependencies with other teams and issue subtasks. Consider those existing tasks that have a close relationship with the current job. At this point, we specify **what is going to be developed**.

The DRI and the leaders will involve all the teams they deem appropriate to cover the needs of all the components:

- Product:
    - Frontend.
    - Framework.
    - Manager.
    - Agent.
    - Ruleset.
- Packages.
- Testing.
- Documentation.

### 2. Requirement validation
|Directors|Chiefs|
|---|---|

Once the task is fully defined, the Product Owners will validate the requirements.

### 3. Estimation
|Development teams|
|---|

Indicate the cost of developing the task, for each team. Take into account which tasks can be parallelized and which have some dependency. 

In this phase, we aim to know:
- Number of days that each team will dedicate to this development.
- Deadline to fully deliver the work. This is the latest delivery date of all teams.
- Total cost as _days × people_.

Based on the estimate, tasks will be **prioritized**.

### 4. Design
|Development teams|
|---|

In this phase, we will be detailing how the task will be done, based on the specified requirements. Here we define, among other things:
- Algorithms.
- Data structures.
- Design patterns.
- Diagrams:
    - Class.
    - State.
    - Entity-relationship.
    - Sequence.
- UI previews.
- QA processes:
    - Functional checks.
    - Performance tests.
    - Footprint analysis.

### 5. Design review
|DRI|Directors|
|---|---|

Developers must sign off on the proposed design prior to implementation.

### 6. Implementation
|Development teams|
|---|

Each team, separately, codifies the task that has been entrusted to them. Then, they may join their jobs to fulfill the dependencies. The result of this phase shall be:
1. One or many PRs.
2. Sample of results:
    - UI screenshots.
    - Inventory.
    - Alerts.
    - Logs.

### 7. Code review & QA
|Team leaders|
|---|

After the implementation, we will do a code review and functional tests.

Perform all these tests that apply:

- Code review:
    - Structure.
    - Coding style.
    - Static code analysis.
    - Dynamic code analysis.
- Deployment:
    - Build.
    - Installation.
    - Upgrade.
- Functional tests:
    - Unit tests.
    - Integration tests.
    - System tests.
- Non-functional tests:
    - Performance.
    - Footprint.

### 8. Feature validation
|Directors|Chiefs|
|---|---|

At this point, the Product Owners shall perform a high-level test of the development through a demo or checking the sample of results got at point 6. They will evaluate the solution and assess whether it meets the established requirements.

### 9. Delivery
|Team leaders|Directors|
|---|---|

After approval from the Product Owners, the task is ready to be delivered. All teams will merge their jobs into the corresponding branches. Then, we will notify the Product Owners and will finish the task.

## Roles

- **DRI**

    The Direct Responsible Individual is **the person who owns the task**. He/she is in charge of delivering the task and managing subtasks with other teams, if necessary. This role will be assigned to the leader of the team that has the most relevance in the development.

- **Development teams**

    The staff is divided into different teams, with specialized skills for each part of the development:
    - [**Frontend**](https://github.com/orgs/wazuh/teams/frontend): Wazuh UI coding and design.
    - [**Framework**](https://github.com/orgs/wazuh/teams/framework): Backend of API & cluster.
    - [**Core**](https://github.com/orgs/wazuh/teams/core): Backend of agent & manager.
    - [**QA**](https://github.com/orgs/wazuh/teams/qa): Testing.
    - [**CICD**](https://github.com/orgs/wazuh/teams/cicd): Packaging & Jenkins integration.
    - [**Cloud**](https://github.com/orgs/wazuh/teams/cloud): Wazuh Cloud platform.
    - [**Threat Intelligence**](https://github.com/orgs/wazuh/teams/threat-intel): Ruleset.

- **Team leaders**

    They are the managers of each of the teams involved in development.

- **Directors & chiefs**

    Directors are managers of larger teams. Together with the chiefs, they will play the role of **Product Owners** to oversee:

    - Technology.
    - User experience.