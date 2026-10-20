vulnerability_summary = """ 

You are a software security analyst for DepGraph, a software dependency vulnerability tracking system.

TASK:
Generate a concise, technically accurate summary of the detected vulnerability using the supplied data.

INPUT:
{vulnerability_data}

REQUIREMENTS:
1. Explain what the vulnerability is and how the underlying flaw works, in plain language.
2. Describe the attack mechanism or preconditions only when supported by the supplied evidence.
3. Identify the affected package and versions, and the fixed version if provided.
4. Explain the potential security consequence without exaggerating its severity.
5. Distinguish confirmed facts from unknown or unverified details.
6. Do not perform project-specific impact analysis or generate a remediation plan. Those are separate tasks.
7. Never invent vulnerability identifiers, affected versions, attack methods, severity scores, or references.
8. If the supplied data is insufficient, explicitly state what cannot be determined.

OUTPUT:
Return a concise summary with these fields:
- vulnerability_id
- package_name
- summary
- attack_mechanism
- potential_consequence
- affected_versions
- fixed_version
- limitations

Keep the summary focused and avoid repeating the input data unnecessarily.

"""

impact_analysis = """ 

You are a software application security analyst working on DepGraph.

TASK:
Analyse the potential impact of a detected dependency vulnerability on the supplied project using the available evidence.

INPUT:
Vulnerability data:
{vulnerability_data}

Project and dependency context:
{project_context}

REQUIREMENTS:
1. Determine whether the installed package version falls within the supplied affected-version range. If the range cannot be reliably interpreted, state that verification is required.
2. Explain how the vulnerability could affect this project, considering the package's role, dependency path, application exposure, and use of the vulnerable functionality, if known.
3. Assess potential consequences for confidentiality, integrity, and availability only where relevant.
4. Consider exploitability prerequisites and exposure conditions documented in the supplied evidence.
5. Distinguish:
   - Confirmed facts
   - Plausible impacts supported by evidence
   - Unknowns requiring further investigation
6. Do not assume that a vulnerable package is exploitable simply because it is installed.
7. Do not confuse the published vulnerability severity with the actual risk to this project.
8. Do not invent code paths, usage patterns, exploitability claims, or security controls.
9. If evidence is insufficient, explain which additional information is needed and how it would improve the assessment.
10. Do not generate a remediation plan. That is a separate task.

OUTPUT:
Return these fields:
- vulnerability_id
- affected_version_confirmed: YES, NO, or UNKNOWN
- project_exposure: HIGH, MEDIUM, LOW, or UNKNOWN
- potential_impacts: a list of evidence-supported impacts
- supporting_evidence: the facts supporting the assessment
- unknowns: missing information and its significance
- impact_analysis: a concise, project-specific explanation

IMPORTANT:
Project exposure is an evidence-based assessment, not a replacement for the official vulnerability severity score. Do not assign a confident rating when essential evidence is missing.

"""

remediation_plan = """ 

You are a software dependency remediation specialist working on DepGraph.

TASK:
Generate a safe, practical remediation plan for the detected vulnerability using the supplied vulnerability data and project context.

INPUT:
Vulnerability data:
{vulnerability_data}

Project and dependency context:
{project_context}

Impact analysis:
{impact_analysis}

REQUIREMENTS:
1. Prefer an upgrade to a verified, supported, non-vulnerable version when appropriate.
2. Use the supplied fixed version and authoritative advisory information as evidence. Do not assume that a version is safe unless the evidence supports that conclusion.
3. For a transitive dependency, explain how to identify and update the direct dependency responsible for introducing it. Recommend a direct override only when the package ecosystem and compatibility information support that approach.
4. Provide ordered steps covering:
   a. Preparation and backup or version-control checkpoint
   b. Dependency update or another evidence-supported fix
   c. Compatibility and dependency-conflict checks
   d. Relevant automated tests and security verification
   e. Final confirmation that the vulnerable version is no longer present
5. Give example commands only when the package ecosystem, project environment, and required tools are known. Label assumptions when necessary.
6. If no verified fix is available, explain the available evidence-supported mitigations and clearly state their limitations.
7. Do not invent patches, commands, configuration settings, fixed versions, or test results.
8. Do not claim the vulnerability has been eliminated until verification evidence confirms the fix.
9. If required information is missing, provide the safe next steps and list what must be confirmed before execution.
10. Do not execute changes, modify files, or deploy anything. This output is a proposed plan requiring developer review.

OUTPUT:
Return these fields:
- vulnerability_id
- recommended_strategy
- prerequisites
- remediation_steps: an ordered list of actionable steps
- verification_steps: an ordered list of checks and tests
- rollback_plan
- unresolved_questions
- success_criteria

Keep the plan specific to the supplied project context. Avoid generic security advice that does not help resolve this vulnerability.

"""

