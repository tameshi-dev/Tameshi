use anyhow::Result;
use async_openai::{
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestMessage, ChatCompletionRequestSystemMessage,
        ChatCompletionRequestUserMessage, ChatCompletionResponseFormat,
        ChatCompletionResponseFormatType, CreateChatCompletionRequestArgs,
    },
    Client,
};
use async_trait::async_trait;
use thiserror::Error;
use std::time::Duration;
use tracing::{debug, error, warn};

#[derive(Debug, Error)]
pub enum LLMError {
    #[error("API error: {0}")]
    ApiError(String),

    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    #[error("Token limit exceeded: {0}")]
    TokenLimitExceeded(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout after {0} seconds")]
    Timeout(u64),
}

#[derive(Debug, Clone)]
pub struct LLMRequest {
    pub system_prompt: String,
    pub user_prompt: String,
    pub temperature: f32,
    pub max_tokens: u32,
    pub response_format: Option<serde_json::Value>,
    pub dump_prompt: bool,
}

#[derive(Debug, Clone)]
pub struct LLMResponse {
    pub content: String,
    pub model: String,
    pub usage: TokenUsage,
}

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[async_trait]
pub trait LLMProvider: Send + Sync {
    async fn analyze(&self, request: LLMRequest) -> Result<LLMResponse, LLMError>;

    fn model_name(&self) -> &str;

    fn max_tokens(&self) -> usize;

    fn estimate_tokens(&self, text: &str) -> usize {
        text.len() / 4
    }
}

pub struct OpenAIProvider {
    client: Client<OpenAIConfig>,
    model: String,
    default_temperature: f32,
    default_max_tokens: u32,
    timeout_seconds: u64,
    max_retries: u32,
}

impl OpenAIProvider {
    pub fn new(model: Option<String>) -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY not set"))?;

        let config = OpenAIConfig::new().with_api_key(api_key);
        let client = Client::with_config(config);

        Ok(Self {
            client,
            model: model.unwrap_or_else(|| "gpt-4o".to_string()),
            default_temperature: 0.2, // Lower for more deterministic outputs
            default_max_tokens: 4000,
            timeout_seconds: 60,
            max_retries: 3,
        })
    }

    pub fn with_config(api_key: String, model: String, temperature: f32, max_tokens: u32) -> Self {
        let config = OpenAIConfig::new().with_api_key(api_key);
        let client = Client::with_config(config);

        Self {
            client,
            model,
            default_temperature: temperature,
            default_max_tokens: max_tokens,
            timeout_seconds: 60,
            max_retries: 3,
        }
    }
    
    fn extract_json_from_text(text: &str) -> Result<String, LLMError> {
        
        if let Some(start) = text.find("```json") {
            if let Some(end) = text[start..].find("```").and_then(|i| {
                if i > 7 { // Make sure it's not the opening ```json
                    Some(start + i)
                } else {
                    text[start + 7..].find("```").map(|j| start + 7 + j)
                }
            }) {
                let json_str = &text[start + 7..end].trim();
                debug!("Found JSON in code block: {}", json_str);
                return Ok(json_str.to_string());
            }
        }
        
        if let Some(start) = text.find('{') {
            let mut depth = 0;
            let mut in_string = false;
            let mut escape_next = false;
            
            let bytes = text.as_bytes();
            let mut end = start;
            
            for (i, &byte) in bytes[start..].iter().enumerate() {
                if escape_next {
                    escape_next = false;
                    continue;
                }
                
                match byte {
                    b'\\' if in_string => escape_next = true,
                    b'"' => in_string = !in_string,
                    b'{' if !in_string => depth += 1,
                    b'}' if !in_string => {
                        depth -= 1;
                        if depth == 0 {
                            end = start + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            
            if end > start {
                let json_str = &text[start..end];
                debug!("Found raw JSON object: {}", json_str);
                return Ok(json_str.to_string());
            }
        }
        
        warn!("Could not extract JSON from response, returning full text");
        Ok(text.to_string())
    }
}

#[async_trait]
impl LLMProvider for OpenAIProvider {
    async fn analyze(&self, request: LLMRequest) -> Result<LLMResponse, LLMError> {
        let is_reasoning_model = self.model.starts_with("o1")
            || self.model.starts_with("o2")
            || self.model.starts_with("o3");
        
        let temperature = if request.temperature > 0.0 {
            request.temperature
        } else {
            self.default_temperature
        };

        let max_tokens = if request.max_tokens > 0 {
            request.max_tokens
        } else {
            self.default_max_tokens
        };

        debug!("Sending request to OpenAI model: {}", self.model);
        debug!("Temperature: {}, Max tokens: {}", temperature, max_tokens);
        debug!("Is reasoning model: {}", is_reasoning_model);

        if request.dump_prompt {
            println!("\n🔍 {} COMPLETE PROMPT DUMP {}", "=".repeat(25), "=".repeat(25));
            println!("🤖 Model: {}", self.model);
            println!("🌡️  Temperature: {}", temperature);
            println!("📏 Max Tokens: {}", max_tokens);
            println!("🧠 Is Reasoning Model: {}", is_reasoning_model);
            println!("\n📝 {} SYSTEM PROMPT {}", "=".repeat(20), "=".repeat(20));
            println!("{}", request.system_prompt);
            println!("\n👤 {} USER PROMPT {}", "=".repeat(22), "=".repeat(22));
            println!("{}", request.user_prompt);
            println!("{}", "=".repeat(70));
            println!();
        }

        let messages = if is_reasoning_model {
            let combined_prompt = format!(
                "Instructions:\n{}\n\nTask:\n{}",
                request.system_prompt,
                request.user_prompt
            );
            
            let user_message = ChatCompletionRequestUserMessage {
                content: async_openai::types::ChatCompletionRequestUserMessageContent::Text(
                    combined_prompt,
                ),
                ..Default::default()
            };
            
            vec![ChatCompletionRequestMessage::User(user_message)]
        } else {
            let system_message = ChatCompletionRequestSystemMessage {
                content: request.system_prompt.clone(),
                ..Default::default()
            };

            let user_message = ChatCompletionRequestUserMessage {
                content: async_openai::types::ChatCompletionRequestUserMessageContent::Text(
                    request.user_prompt.clone(),
                ),
                ..Default::default()
            };

            vec![
                ChatCompletionRequestMessage::System(system_message),
                ChatCompletionRequestMessage::User(user_message),
            ]
        };

        let mut request_builder = CreateChatCompletionRequestArgs::default();
        request_builder.model(&self.model).messages(messages);

        if is_reasoning_model {


            debug!("Using reasoning model configuration (no temperature, no JSON format)");
        } else {
            request_builder
                .temperature(temperature)
                .max_tokens(max_tokens)
                .response_format(ChatCompletionResponseFormat {
                    r#type: ChatCompletionResponseFormatType::JsonObject,
                });
        }

        let api_request = request_builder
            .build()
            .map_err(|e| LLMError::ApiError(e.to_string()))?;

        let mut attempt = 0;
        let max_attempts = self.max_retries;
        let mut last_error = None;

        let response = loop {
            attempt += 1;
            debug!("API call attempt {}/{}", attempt, max_attempts);

            match self.client.chat().create(api_request.clone()).await {
                Ok(response) => break response,
                Err(e) => {
                    warn!("OpenAI API error (attempt {}): {}", attempt, e);
                    last_error = Some(e.to_string());

                    if attempt >= max_attempts {
                        return Err(LLMError::ApiError(
                            last_error.unwrap_or_else(|| "Unknown error".to_string()),
                        ));
                    }

                    let wait_time = if last_error
                        .as_ref()
                        .map(|s| s.contains("rate"))
                        .unwrap_or(false)
                    {
                        Duration::from_secs(2_u64.pow(attempt))
                    } else {
                        Duration::from_millis(100 * attempt as u64)
                    };

                    tokio::time::sleep(wait_time).await;
                }
            }
        };

        let mut content = response
            .choices
            .first()
            .and_then(|choice| choice.message.content.clone())
            .ok_or_else(|| LLMError::InvalidResponse("No content in response".to_string()))?;

        if is_reasoning_model {
            debug!("Extracting JSON from o1 model response");
            content = Self::extract_json_from_text(&content)?;
        }

        let usage = response
            .usage
            .map(|u| TokenUsage {
                prompt_tokens: u.prompt_tokens,
                completion_tokens: u.completion_tokens,
                total_tokens: u.total_tokens,
            })
            .unwrap_or_default();

        debug!("Received response with {} tokens", usage.total_tokens);

        Ok(LLMResponse {
            content,
            model: response.model,
            usage,
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn max_tokens(&self) -> usize {
        if self.model.starts_with("o1") || self.model.starts_with("o2") || self.model.starts_with("o3") {
            return 200000; // Reasoning models typically have 200K context
        }

        match self.model.as_str() {
            "gpt-4o" | "gpt-4-turbo" => 128000,
            "gpt-4" => 8192,
            "gpt-3.5-turbo" => 16385,
            _ => 4096,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_estimation() {
        let provider = OpenAIProvider::new(None).unwrap_or_else(|_| {
            OpenAIProvider::with_config("test_key".to_string(), "gpt-4o".to_string(), 0.2, 4000)
        });

        let text = "This is a test string for token estimation.";
        let estimated = provider.estimate_tokens(text);

        assert!(estimated > 0);
        assert!(estimated < text.len());
    }
}
