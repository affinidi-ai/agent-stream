use chrono::Utc;
use samael::attribute::{Attribute, AttributeValue};
use samael::schema::{Assertion, AttributeStatement, Issuer, Subject, SubjectNameID};

pub(super) fn statement(attributes: &[(&str, &[&str])]) -> AttributeStatement {
    AttributeStatement {
        attributes: attributes
            .iter()
            .map(|(name, values)| Attribute {
                friendly_name: None,
                name: Some(name.to_string()),
                name_format: None,
                values: values
                    .iter()
                    .map(|value| AttributeValue {
                        attribute_type: None,
                        value: Some(value.to_string()),
                    })
                    .collect(),
            })
            .collect(),
    }
}

pub(super) fn assertion(
    name_id: Option<&str>,
    statements: Vec<AttributeStatement>,
) -> Assertion {
    Assertion {
        id: "assertion-1".to_string(),
        issue_instant: Utc::now(),
        version: "2.0".to_string(),
        issuer: Issuer {
            name_qualifier: None,
            sp_name_qualifier: None,
            format: None,
            sp_provided_id: None,
            value: Some("https://idp.example".to_string()),
        },
        signature: None,
        subject: name_id.map(|value| Subject {
            name_id: Some(SubjectNameID {
                format: None,
                value: value.to_string(),
            }),
            subject_confirmations: None,
        }),
        conditions: None,
        authn_statements: None,
        attribute_statements: Some(statements),
    }
}
