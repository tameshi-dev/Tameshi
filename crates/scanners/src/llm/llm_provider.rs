use crate::llm::provider::{LLMProvider as LLMProviderTrait, LLMRequest, OpenAIProvider};
use anyhow::Result;

pub struct LLMProvider {
    provider: OpenAIProvider,
}

impl LLMProvider {
    pub fn new(model: String) -> Self {
        let provider = OpenAIProvider::new(Some(model)).expect("Failed to create OpenAI provider");
        Self { provider }
    }

    pub async fn analyze(&self, prompt: &str) -> Result<String> {
        let request = LLMRequest {
            system_prompt: "You are a smart contract security analyzer.".to_string(),
            user_prompt: prompt.to_string(),
            temperature: 0.1,
            max_tokens: 2000,
            response_format: None,
            dump_prompt: false,
        };

        let response = self.provider.analyze(request).await?;
        Ok(response.content)
    }
}
