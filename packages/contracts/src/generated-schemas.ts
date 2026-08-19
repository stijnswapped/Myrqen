/* GENERATED FILE - do not edit.
 * Source: schemas/*.json
 * Regenerate: node scripts/generate-schema-module.mjs
 */

export const REPORT_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.myrqen.invalid/report.schema.json",
  "title": "Myrqen Report",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schemaVersion",
    "id",
    "generatedAt",
    "project",
    "scan",
    "summary",
    "findings",
    "coverage",
    "limitations"
  ],
  "$defs": {
    "severityCounts": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "critical",
        "high",
        "medium",
        "low",
        "info"
      ],
      "properties": {
        "critical": {
          "type": "integer",
          "minimum": 0
        },
        "high": {
          "type": "integer",
          "minimum": 0
        },
        "medium": {
          "type": "integer",
          "minimum": 0
        },
        "low": {
          "type": "integer",
          "minimum": 0
        },
        "info": {
          "type": "integer",
          "minimum": 0
        }
      }
    },
    "verificationCounts": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "verified",
        "strong_evidence",
        "needs_review"
      ],
      "properties": {
        "verified": {
          "type": "integer",
          "minimum": 0
        },
        "strong_evidence": {
          "type": "integer",
          "minimum": 0
        },
        "needs_review": {
          "type": "integer",
          "minimum": 0
        }
      }
    }
  },
  "properties": {
    "schemaVersion": {
      "const": "1.0.0"
    },
    "id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "cloudReportId": {
      "type": "string",
      "maxLength": 128
    },
    "generatedAt": {
      "type": "string",
      "format": "date-time"
    },
    "project": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "name",
        "workspaceKind"
      ],
      "properties": {
        "name": {
          "type": "string",
          "maxLength": 200
        },
        "workspaceKind": {
          "enum": [
            "personal",
            "team"
          ]
        },
        "workspaceName": {
          "type": "string",
          "maxLength": 200
        },
        "repositoryLabel": {
          "type": "string",
          "maxLength": 300
        }
      }
    },
    "scan": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "effortRequested",
        "effortResolved",
        "durationMs",
        "agent",
        "tokenUsage",
        "scope"
      ],
      "properties": {
        "effortRequested": {
          "enum": [
            "low",
            "high",
            "xhigh",
            "ultra",
            "auto"
          ]
        },
        "effortResolved": {
          "enum": [
            "low",
            "high",
            "xhigh",
            "ultra"
          ]
        },
        "effortProfile": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "reasoningPasses",
            "validationPasses",
            "maxParallelInvestigations",
            "wallClockBudgetMs",
            "falsePositiveChallengePass",
            "identityMatrixDepth",
            "breadth"
          ],
          "properties": {
            "reasoningPasses": {
              "type": "integer",
              "minimum": 1
            },
            "validationPasses": {
              "type": "integer",
              "minimum": 1
            },
            "maxParallelInvestigations": {
              "type": "integer",
              "minimum": 1
            },
            "wallClockBudgetMs": {
              "type": "integer",
              "minimum": 1000
            },
            "falsePositiveChallengePass": {
              "type": "boolean"
            },
            "identityMatrixDepth": {
              "type": "integer",
              "minimum": 0,
              "maximum": 3
            },
            "breadth": {
              "enum": [
                "focused",
                "broad",
                "comprehensive"
              ]
            }
          }
        },
        "startedAt": {
          "type": "string",
          "format": "date-time"
        },
        "completedAt": {
          "type": "string",
          "format": "date-time"
        },
        "durationMs": {
          "type": "integer",
          "minimum": 0
        },
        "agent": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "name"
          ],
          "properties": {
            "name": {
              "type": "string",
              "maxLength": 120
            },
            "version": {
              "type": "string",
              "maxLength": 120
            },
            "model": {
              "type": "string",
              "maxLength": 200
            }
          }
        },
        "host": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "osFamily",
            "arch"
          ],
          "properties": {
            "osFamily": {
              "type": "string",
              "maxLength": 60
            },
            "arch": {
              "type": "string",
              "maxLength": 40
            },
            "runtimeVersion": {
              "type": "string",
              "maxLength": 60
            },
            "cliVersion": {
              "type": "string",
              "maxLength": 60
            },
            "isolatedRuntimeAvailable": {
              "type": "boolean"
            }
          }
        },
        "tokenUsage": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "source"
          ],
          "properties": {
            "source": {
              "enum": [
                "exact",
                "estimated",
                "unavailable"
              ]
            },
            "count": {
              "type": "integer",
              "minimum": 0
            },
            "estimator": {
              "type": "string",
              "maxLength": 160
            }
          }
        },
        "scope": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "localTargets",
            "externalTargets"
          ],
          "properties": {
            "localTargets": {
              "type": "array",
              "items": {
                "type": "string",
                "maxLength": 1000
              },
              "maxItems": 128
            },
            "externalTargets": {
              "type": "array",
              "maxItems": 64,
              "items": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                  "target",
                  "authorized"
                ],
                "properties": {
                  "target": {
                    "type": "string",
                    "maxLength": 1000
                  },
                  "authorized": {
                    "const": true
                  },
                  "authorizedAt": {
                    "type": "string",
                    "format": "date-time"
                  },
                  "method": {
                    "enum": [
                      "interactive_confirmation",
                      "preauthorized_project_config"
                    ]
                  }
                }
              }
            }
          }
        },
        "phases": {
          "type": "array",
          "maxItems": 64,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "phase",
              "state"
            ],
            "properties": {
              "phase": {
                "enum": [
                  "preflight",
                  "scope",
                  "discovery",
                  "source_review",
                  "runtime_validation",
                  "access_control",
                  "validation",
                  "reporting"
                ]
              },
              "state": {
                "enum": [
                  "pending",
                  "running",
                  "complete",
                  "skipped"
                ]
              },
              "startedAt": {
                "type": "string",
                "format": "date-time"
              },
              "completedAt": {
                "type": "string",
                "format": "date-time"
              },
              "durationMs": {
                "type": "integer",
                "minimum": 0
              },
              "note": {
                "type": "string",
                "maxLength": 500
              }
            }
          }
        },
        "stack": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "languages",
            "frameworks",
            "packageManagers",
            "services"
          ],
          "properties": {
            "languages": {
              "type": "array",
              "items": {
                "type": "string",
                "maxLength": 80
              },
              "maxItems": 40
            },
            "frameworks": {
              "type": "array",
              "items": {
                "type": "string",
                "maxLength": 80
              },
              "maxItems": 40
            },
            "packageManagers": {
              "type": "array",
              "items": {
                "type": "string",
                "maxLength": 80
              },
              "maxItems": 20
            },
            "services": {
              "type": "array",
              "items": {
                "type": "string",
                "maxLength": 200
              },
              "maxItems": 40
            }
          }
        }
      }
    },
    "authorization": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "destructiveActionsAllowed",
        "prohibitedActions",
        "externalTargetAuthorization",
        "localTargetsInScope"
      ],
      "properties": {
        "destructiveActionsAllowed": {
          "const": false
        },
        "prohibitedActions": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 80
          },
          "maxItems": 64
        },
        "externalTargetAuthorization": {
          "const": "exact_origin_only"
        },
        "localTargetsInScope": {
          "type": "boolean"
        },
        "notes": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 500
          },
          "maxItems": 32
        }
      }
    },
    "summary": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "findingCount",
        "severityCounts",
        "verificationCounts"
      ],
      "properties": {
        "findingCount": {
          "type": "integer",
          "minimum": 0
        },
        "severityCounts": {
          "$ref": "#/$defs/severityCounts"
        },
        "verificationCounts": {
          "$ref": "#/$defs/verificationCounts"
        },
        "candidateCount": {
          "type": "integer",
          "minimum": 0
        },
        "duplicateCount": {
          "type": "integer",
          "minimum": 0
        },
        "fixedCount": {
          "type": "integer",
          "minimum": 0
        }
      }
    },
    "findings": {
      "type": "array",
      "maxItems": 5000,
      "items": {
        "$ref": "https://schemas.myrqen.invalid/finding.schema.json"
      }
    },
    "coverage": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 1000
      },
      "maxItems": 200
    },
    "coverageAreas": {
      "type": "array",
      "maxItems": 200,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "area",
          "assessed"
        ],
        "properties": {
          "area": {
            "type": "string",
            "maxLength": 200
          },
          "assessed": {
            "type": "boolean"
          },
          "method": {
            "type": "string",
            "maxLength": 300
          },
          "note": {
            "type": "string",
            "maxLength": 1000
          }
        }
      }
    },
    "limitations": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 1000
      },
      "maxItems": 200
    },
    "methodologyVersion": {
      "type": "string",
      "maxLength": 40
    }
  }
} as const;

export const FINDING_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.myrqen.invalid/finding.schema.json",
  "title": "Myrqen Finding",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "id",
    "title",
    "category",
    "severity",
    "verification",
    "summary",
    "impact",
    "affected",
    "evidence",
    "remediation",
    "verificationPlan"
  ],
  "$defs": {
    "evidence": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "kind",
        "description"
      ],
      "properties": {
        "kind": {
          "enum": [
            "source",
            "runtime",
            "identity_differential",
            "configuration",
            "dependency",
            "other"
          ]
        },
        "description": {
          "type": "string",
          "minLength": 1,
          "maxLength": 12000
        },
        "snippet": {
          "type": "string",
          "maxLength": 24000
        },
        "location": {
          "type": "string",
          "maxLength": 1000
        },
        "redacted": {
          "type": "boolean"
        }
      }
    }
  },
  "properties": {
    "id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "title": {
      "type": "string",
      "minLength": 1,
      "maxLength": 240
    },
    "category": {
      "type": "string",
      "minLength": 1,
      "maxLength": 120
    },
    "taxonomy": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 64
      },
      "maxItems": 16
    },
    "severity": {
      "enum": [
        "critical",
        "high",
        "medium",
        "low",
        "info"
      ]
    },
    "verification": {
      "enum": [
        "verified",
        "strong_evidence",
        "needs_review"
      ]
    },
    "summary": {
      "type": "string",
      "minLength": 1,
      "maxLength": 8000
    },
    "impact": {
      "type": "string",
      "minLength": 1,
      "maxLength": 8000
    },
    "affected": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "component"
      ],
      "properties": {
        "component": {
          "type": "string",
          "minLength": 1,
          "maxLength": 500
        },
        "file": {
          "type": "string",
          "maxLength": 1000
        },
        "lineStart": {
          "type": "integer",
          "minimum": 1
        },
        "lineEnd": {
          "type": "integer",
          "minimum": 1
        },
        "route": {
          "type": "string",
          "maxLength": 1000
        },
        "origin": {
          "type": "string",
          "maxLength": 1000
        }
      }
    },
    "evidence": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": {
        "$ref": "#/$defs/evidence"
      }
    },
    "corroboration": {
      "type": "array",
      "maxItems": 64,
      "items": {
        "$ref": "#/$defs/evidence"
      }
    },
    "remediation": {
      "type": "string",
      "minLength": 1,
      "maxLength": 12000
    },
    "verificationPlan": {
      "type": "string",
      "minLength": 1,
      "maxLength": 8000
    },
    "reproduction": {
      "type": "string",
      "maxLength": 12000
    },
    "references": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 500
      },
      "maxItems": 32
    },
    "fingerprint": {
      "type": "string",
      "maxLength": 128
    },
    "secretReferences": {
      "type": "array",
      "maxItems": 128,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "label",
          "kind",
          "fingerprint"
        ],
        "properties": {
          "label": {
            "type": "string",
            "maxLength": 200
          },
          "kind": {
            "type": "string",
            "maxLength": 80
          },
          "fingerprint": {
            "type": "string",
            "maxLength": 128
          },
          "location": {
            "type": "string",
            "maxLength": 1000
          }
        }
      }
    },
    "status": {
      "enum": [
        "open",
        "fix_suggested",
        "fix_applied",
        "fixed_verified",
        "accepted_risk",
        "false_positive"
      ]
    },
    "fixedAt": {
      "type": "string",
      "format": "date-time"
    },
    "fixHistory": {
      "type": "array",
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "at",
          "action",
          "verified"
        ],
        "properties": {
          "at": {
            "type": "string",
            "format": "date-time"
          },
          "action": {
            "enum": [
              "suggested",
              "applied",
              "verified",
              "verification_failed",
              "reverted"
            ]
          },
          "verified": {
            "type": "boolean"
          },
          "changedFiles": {
            "type": "array",
            "items": {
              "type": "string",
              "maxLength": 1000
            },
            "maxItems": 200
          },
          "note": {
            "type": "string",
            "maxLength": 4000
          }
        }
      }
    },
    "firstSeenAt": {
      "type": "string",
      "format": "date-time"
    },
    "tags": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 80
      },
      "maxItems": 32
    }
  }
} as const;

export const FINDING_SUBMISSION_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://schemas.myrqen.invalid/finding-submission.schema.json",
  "title": "Myrqen finding submission from host agent",
  "description": "The host agent proposes a finding. The local CLI owns identity, fingerprint, dedupe, redaction, and verification bookkeeping.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "title",
    "category",
    "severity",
    "verification",
    "summary",
    "impact",
    "affected",
    "evidence",
    "remediation",
    "verificationPlan"
  ],
  "properties": {
    "title": {
      "type": "string",
      "minLength": 4,
      "maxLength": 240
    },
    "category": {
      "type": "string",
      "minLength": 2,
      "maxLength": 120
    },
    "taxonomy": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 64
      },
      "maxItems": 16
    },
    "severity": {
      "enum": [
        "critical",
        "high",
        "medium",
        "low",
        "info"
      ]
    },
    "verification": {
      "enum": [
        "verified",
        "strong_evidence",
        "needs_review"
      ]
    },
    "summary": {
      "type": "string",
      "minLength": 20,
      "maxLength": 8000
    },
    "impact": {
      "type": "string",
      "minLength": 20,
      "maxLength": 8000
    },
    "affected": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "component"
      ],
      "properties": {
        "component": {
          "type": "string",
          "minLength": 1,
          "maxLength": 500
        },
        "file": {
          "type": "string",
          "maxLength": 1000
        },
        "lineStart": {
          "type": "integer",
          "minimum": 1
        },
        "lineEnd": {
          "type": "integer",
          "minimum": 1
        },
        "route": {
          "type": "string",
          "maxLength": 1000
        },
        "origin": {
          "type": "string",
          "maxLength": 1000
        }
      }
    },
    "evidence": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "kind",
          "description"
        ],
        "properties": {
          "kind": {
            "enum": [
              "source",
              "runtime",
              "identity_differential",
              "configuration",
              "dependency",
              "other"
            ]
          },
          "description": {
            "type": "string",
            "minLength": 10,
            "maxLength": 12000
          },
          "snippet": {
            "type": "string",
            "maxLength": 24000
          },
          "location": {
            "type": "string",
            "maxLength": 1000
          },
          "redacted": {
            "type": "boolean"
          }
        }
      }
    },
    "remediation": {
      "type": "string",
      "minLength": 20,
      "maxLength": 12000
    },
    "verificationPlan": {
      "type": "string",
      "minLength": 10,
      "maxLength": 8000
    },
    "reproduction": {
      "type": "string",
      "maxLength": 12000
    },
    "references": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 500
      },
      "maxItems": 32
    },
    "tags": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 80
      },
      "maxItems": 32
    }
  }
} as const;

export const SCAN_EVENT_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Myrqen safe live scan event",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "eventId",
    "reportId",
    "type",
    "occurredAt"
  ],
  "properties": {
    "eventId": {
      "type": "string",
      "maxLength": 128
    },
    "reportId": {
      "type": "string",
      "maxLength": 128
    },
    "occurredAt": {
      "type": "string",
      "format": "date-time"
    },
    "type": {
      "enum": [
        "report_created",
        "phase_started",
        "phase_completed",
        "aggregate_updated",
        "warning_safe",
        "scan_completed",
        "scan_failed"
      ]
    },
    "phase": {
      "enum": [
        "preflight",
        "scope",
        "discovery",
        "source_review",
        "runtime_validation",
        "access_control",
        "validation",
        "reporting"
      ]
    },
    "safeCode": {
      "type": "string",
      "pattern": "^[A-Z0-9_]{1,80}$"
    },
    "message": {
      "type": "string",
      "maxLength": 300
    },
    "durationMs": {
      "type": "integer",
      "minimum": 0
    },
    "aggregate": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "candidateCount": {
          "type": "integer",
          "minimum": 0
        },
        "validatedCount": {
          "type": "integer",
          "minimum": 0
        },
        "critical": {
          "type": "integer",
          "minimum": 0
        },
        "high": {
          "type": "integer",
          "minimum": 0
        },
        "medium": {
          "type": "integer",
          "minimum": 0
        },
        "low": {
          "type": "integer",
          "minimum": 0
        },
        "info": {
          "type": "integer",
          "minimum": 0
        }
      }
    }
  },
  "$id": "https://schemas.myrqen.invalid/scan-event.schema.json"
} as const;

export const SHARE_POLICY_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Myrqen share projection policy",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "sections",
    "findings",
    "fields"
  ],
  "properties": {
    "version": {
      "const": 1
    },
    "sections": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "mode",
        "ids"
      ],
      "properties": {
        "mode": {
          "enum": [
            "allow_all",
            "allow_only"
          ]
        },
        "ids": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 128
          },
          "maxItems": 256
        }
      }
    },
    "findings": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "mode",
        "ids"
      ],
      "properties": {
        "mode": {
          "enum": [
            "allow_all",
            "allow_only"
          ]
        },
        "ids": {
          "type": "array",
          "items": {
            "type": "string",
            "maxLength": 128
          },
          "maxItems": 5000
        },
        "maxSeverity": {
          "enum": [
            "critical",
            "high",
            "medium",
            "low",
            "info"
          ]
        }
      }
    },
    "fields": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "evidence": {
          "type": "boolean"
        },
        "code": {
          "type": "boolean"
        },
        "reproduction": {
          "type": "boolean"
        },
        "remediation": {
          "type": "boolean"
        },
        "metadata": {
          "type": "boolean"
        }
      }
    },
    "anonymize": {
      "type": "boolean"
    }
  },
  "$id": "https://schemas.myrqen.invalid/share-policy.schema.json"
} as const;

export const PROJECT_BINDING_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Myrqen project binding",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "version",
    "kind",
    "workspaceId",
    "projectId"
  ],
  "properties": {
    "version": {
      "const": 1
    },
    "kind": {
      "enum": [
        "team"
      ]
    },
    "workspaceId": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    },
    "projectId": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    }
  }
} as const;

export const UPDATE_MANIFEST_SCHEMA = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Myrqen signed update manifest payload",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schemaVersion",
    "releaseVersion",
    "channel",
    "publishedAt",
    "artifacts",
    "revokedVersions",
    "keyId"
  ],
  "properties": {
    "schemaVersion": {
      "const": 1
    },
    "releaseVersion": {
      "type": "string",
      "maxLength": 80
    },
    "channel": {
      "enum": [
        "stable",
        "beta",
        "canary"
      ]
    },
    "publishedAt": {
      "type": "string",
      "format": "date-time"
    },
    "minimumClientVersion": {
      "type": "string",
      "maxLength": 80
    },
    "revokedVersions": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "range",
          "reasonCode"
        ],
        "properties": {
          "range": {
            "type": "string",
            "maxLength": 160
          },
          "reasonCode": {
            "type": "string",
            "maxLength": 80
          }
        }
      }
    },
    "artifacts": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": [
          "os",
          "arch",
          "url",
          "sha256",
          "size"
        ],
        "properties": {
          "os": {
            "enum": [
              "darwin",
              "windows",
              "linux"
            ]
          },
          "arch": {
            "enum": [
              "x64",
              "arm64"
            ]
          },
          "url": {
            "type": "string",
            "format": "uri"
          },
          "sha256": {
            "type": "string",
            "pattern": "^[a-f0-9]{64}$"
          },
          "size": {
            "type": "integer",
            "minimum": 1
          }
        }
      }
    },
    "skillBundle": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "version": {
          "type": "string"
        },
        "sha256": {
          "type": "string",
          "pattern": "^[a-f0-9]{64}$"
        }
      }
    },
    "keyId": {
      "type": "string",
      "maxLength": 120
    }
  }
} as const;

export const ALL_SCHEMAS = [
  REPORT_SCHEMA,
  FINDING_SCHEMA,
  FINDING_SUBMISSION_SCHEMA,
  SCAN_EVENT_SCHEMA,
  SHARE_POLICY_SCHEMA,
  PROJECT_BINDING_SCHEMA,
  UPDATE_MANIFEST_SCHEMA,
] as const;
