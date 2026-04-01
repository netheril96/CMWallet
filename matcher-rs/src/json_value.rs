use nanoserde::DeJson;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    String(String),
    Number(f64),
    Bool(bool),
    Null,
    Array(Vec<JsonValue>),
    Object(HashMap<String, JsonValue>),
}

impl Default for JsonValue {
    fn default() -> Self {
        JsonValue::Null
    }
}

impl DeJson for JsonValue {
    fn de_json(
        state: &mut nanoserde::DeJsonState,
        input: &mut std::str::Chars,
    ) -> Result<Self, nanoserde::DeJsonErr> {
        match state.tok {
            nanoserde::DeJsonTok::Str => {
                let s = state.strbuf.clone();
                state.next_tok(input)?;
                Ok(JsonValue::String(s))
            }
            nanoserde::DeJsonTok::F64(n) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(n))
            }
            nanoserde::DeJsonTok::U64(n) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(n as f64))
            }
            nanoserde::DeJsonTok::I64(n) => {
                state.next_tok(input)?;
                Ok(JsonValue::Number(n as f64))
            }
            nanoserde::DeJsonTok::Bool(b) => {
                state.next_tok(input)?;
                Ok(JsonValue::Bool(b))
            }
            nanoserde::DeJsonTok::Null => {
                state.next_tok(input)?;
                Ok(JsonValue::Null)
            }
            nanoserde::DeJsonTok::BlockOpen => {
                state.next_tok(input)?;
                let mut arr = Vec::new();
                while state.tok != nanoserde::DeJsonTok::BlockClose {
                    arr.push(JsonValue::de_json(state, input)?);
                    if state.tok == nanoserde::DeJsonTok::Comma {
                        state.next_tok(input)?;
                    }
                }
                state.next_tok(input)?;
                Ok(JsonValue::Array(arr))
            }
            nanoserde::DeJsonTok::CurlyOpen => {
                state.next_tok(input)?;
                let mut obj = HashMap::new();
                while state.tok != nanoserde::DeJsonTok::CurlyClose {
                    if state.tok == nanoserde::DeJsonTok::Str {
                        let key = state.strbuf.clone();
                        state.next_tok(input)?;
                        if state.tok != nanoserde::DeJsonTok::Colon {
                            return Err(state.err_exp("Colon"));
                        }
                        state.next_tok(input)?;
                        obj.insert(key, JsonValue::de_json(state, input)?);
                        if state.tok == nanoserde::DeJsonTok::Comma {
                            state.next_tok(input)?;
                        }
                    } else {
                        return Err(state.err_exp("String key"));
                    }
                }
                state.next_tok(input)?;
                Ok(JsonValue::Object(obj))
            }
            _ => Err(state.err_exp("JsonValue")),
        }
    }
}
