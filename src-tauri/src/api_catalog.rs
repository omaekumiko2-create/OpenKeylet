use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiProfile {
    pub display_name: &'static str,
    pub default_base_url: &'static str,
    pub auth_type: &'static str,
    pub auth_header: &'static str,
    pub auth_location: &'static str,
    pub auth_prefix: &'static str,
}

const UNKNOWN: ApiProfile = ApiProfile {
    display_name: "API",
    default_base_url: "",
    auth_type: "bearer",
    auth_header: "Authorization",
    auth_location: "header",
    auth_prefix: "Bearer",
};

type ApiProfileEntry = (
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
    ApiProfile,
);

const PROFILES: &[ApiProfileEntry] = &[
    (
        &["api.stripe.com"],
        &["stripe"],
        &["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
        ApiProfile {
            display_name: "Stripe",
            default_base_url: "https://api.stripe.com/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.anthropic.com"],
        &["anthropic", "claude"],
        &["sk-ant-"],
        ApiProfile {
            display_name: "Anthropic",
            default_base_url: "https://api.anthropic.com/v1/",
            auth_type: "apiKey",
            auth_header: "x-api-key",
            auth_location: "header",
            auth_prefix: "",
        },
    ),
    (
        &["openrouter.ai"],
        &["openrouter"],
        &["sk-or-v1-"],
        ApiProfile {
            display_name: "OpenRouter",
            default_base_url: "https://openrouter.ai/api/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.groq.com"],
        &["groq"],
        &["gsk_"],
        ApiProfile {
            display_name: "Groq",
            default_base_url: "https://api.groq.com/openai/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.openai.com"],
        &["openai", "chatgpt api"],
        &["sk-proj-", "sk-svcacct-"],
        ApiProfile {
            display_name: "OpenAI",
            default_base_url: "https://api.openai.com/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.github.com"],
        &["github"],
        &["github_pat_", "ghp_", "gho_", "ghu_", "ghs_"],
        ApiProfile {
            display_name: "GitHub",
            default_base_url: "https://api.github.com/",
            ..UNKNOWN
        },
    ),
    (
        &["api.cloudflare.com"],
        &["cloudflare"],
        &["cfut_"],
        ApiProfile {
            display_name: "Cloudflare",
            default_base_url: "https://api.cloudflare.com/client/v4/",
            ..UNKNOWN
        },
    ),
    (
        &["generativelanguage.googleapis.com"],
        &["gemini", "google ai"],
        &["AIza"],
        ApiProfile {
            display_name: "Google Gemini",
            default_base_url: "https://generativelanguage.googleapis.com/v1beta/",
            auth_type: "apiKey",
            auth_header: "key",
            auth_location: "query",
            auth_prefix: "",
        },
    ),
    (
        &["api.deepseek.com"],
        &["deepseek"],
        &[],
        ApiProfile {
            display_name: "DeepSeek",
            default_base_url: "https://api.deepseek.com/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.x.ai"],
        &["xai", "grok"],
        &["xai-"],
        ApiProfile {
            display_name: "xAI",
            default_base_url: "https://api.x.ai/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api-inference.huggingface.co", "huggingface.co"],
        &["huggingface", "hugging face", "hf_token"],
        &["hf_"],
        ApiProfile {
            display_name: "Hugging Face",
            default_base_url: "https://huggingface.co/api/",
            ..UNKNOWN
        },
    ),
    (
        &["api.resend.com"],
        &["resend"],
        &["re_"],
        ApiProfile {
            display_name: "Resend",
            default_base_url: "https://api.resend.com/",
            ..UNKNOWN
        },
    ),
    (
        &["slack.com"],
        &["slack"],
        &["xoxb-", "xoxp-", "xapp-"],
        ApiProfile {
            display_name: "Slack",
            default_base_url: "https://slack.com/api/",
            ..UNKNOWN
        },
    ),
    (
        &["api.linear.app"],
        &["linear"],
        &["lin_api_"],
        ApiProfile {
            display_name: "Linear",
            default_base_url: "https://api.linear.app/graphql",
            auth_type: "apiKey",
            auth_header: "Authorization",
            auth_location: "header",
            auth_prefix: "",
        },
    ),
    (
        &["api.notion.com"],
        &["notion"],
        &["ntn_"],
        ApiProfile {
            display_name: "Notion",
            default_base_url: "https://api.notion.com/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["gitlab.com"],
        &["gitlab"],
        &["glpat-"],
        ApiProfile {
            display_name: "GitLab",
            default_base_url: "https://gitlab.com/api/v4/",
            auth_type: "apiKey",
            auth_header: "PRIVATE-TOKEN",
            auth_location: "header",
            auth_prefix: "",
        },
    ),
    (
        &["api.digitalocean.com"],
        &["digitalocean"],
        &["dop_v1_", "doo_v1_"],
        ApiProfile {
            display_name: "DigitalOcean",
            default_base_url: "https://api.digitalocean.com/v2/",
            ..UNKNOWN
        },
    ),
    (
        &["api.vercel.com"],
        &["vercel"],
        &["vercel_"],
        ApiProfile {
            display_name: "Vercel",
            default_base_url: "https://api.vercel.com/",
            ..UNKNOWN
        },
    ),
    (
        &["api.supabase.com", "supabase.co"],
        &["supabase"],
        &["sbp_"],
        ApiProfile {
            display_name: "Supabase",
            default_base_url: "https://api.supabase.com/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["registry.npmjs.org"],
        &["npm"],
        &["npm_"],
        ApiProfile {
            display_name: "npm",
            default_base_url: "https://registry.npmjs.org/",
            ..UNKNOWN
        },
    ),
    (
        &["upload.pypi.org", "pypi.org"],
        &["pypi"],
        &["pypi-"],
        ApiProfile {
            display_name: "PyPI",
            default_base_url: "https://upload.pypi.org/",
            ..UNKNOWN
        },
    ),
    (
        &["api.tavily.com"],
        &["tavily"],
        &["tvly-"],
        ApiProfile {
            display_name: "Tavily",
            default_base_url: "https://api.tavily.com/",
            ..UNKNOWN
        },
    ),
    (
        &["api.firecrawl.dev"],
        &["firecrawl"],
        &["fc-"],
        ApiProfile {
            display_name: "Firecrawl",
            default_base_url: "https://api.firecrawl.dev/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.perplexity.ai"],
        &["perplexity"],
        &["pplx-"],
        ApiProfile {
            display_name: "Perplexity",
            default_base_url: "https://api.perplexity.ai/",
            ..UNKNOWN
        },
    ),
    (
        &["sentry.io"],
        &["sentry"],
        &["sntrys_", "sntryu_"],
        ApiProfile {
            display_name: "Sentry",
            default_base_url: "https://sentry.io/api/0/",
            ..UNKNOWN
        },
    ),
    (
        &["api.sendgrid.com"],
        &["sendgrid"],
        &["SG."],
        ApiProfile {
            display_name: "SendGrid",
            default_base_url: "https://api.sendgrid.com/v3/",
            ..UNKNOWN
        },
    ),
    (
        &["dashscope.aliyuncs.com"],
        &["dashscope", "qwen", "tongyi"],
        &[],
        ApiProfile {
            display_name: "DashScope",
            default_base_url: "https://dashscope.aliyuncs.com/compatible-mode/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.moonshot.cn"],
        &["moonshot", "kimi"],
        &[],
        ApiProfile {
            display_name: "Moonshot",
            default_base_url: "https://api.moonshot.cn/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["api.siliconflow.cn"],
        &["siliconflow"],
        &[],
        ApiProfile {
            display_name: "SiliconFlow",
            default_base_url: "https://api.siliconflow.cn/v1/",
            ..UNKNOWN
        },
    ),
    (
        &["open.bigmodel.cn"],
        &["zhipu", "bigmodel", "glm"],
        &[],
        ApiProfile {
            display_name: "Zhipu AI",
            default_base_url: "https://open.bigmodel.cn/api/paas/v4/",
            ..UNKNOWN
        },
    ),
];

pub fn infer(name: &str, base_url: &str, secret: &str) -> ApiProfile {
    let text = format!("{name} {base_url}").to_ascii_lowercase();
    for (hosts, aliases, _, profile) in PROFILES {
        if hosts.iter().any(|host| text.contains(host))
            || aliases.iter().any(|alias| text.contains(alias))
        {
            return *profile;
        }
    }
    for (_, _, prefixes, profile) in PROFILES {
        if prefixes.iter().any(|prefix| secret.starts_with(prefix)) {
            return *profile;
        }
    }
    UNKNOWN
}

pub fn normalize_base_url(raw: &str, fallback: &str) -> anyhow::Result<String> {
    let raw = if raw.trim().is_empty() {
        fallback.trim()
    } else {
        raw.trim()
    };
    if raw.is_empty() {
        return Ok(String::new());
    }
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).map_err(|_| anyhow::anyhow!("Invalid API URL"))?;
    Ok(url.to_string())
}

pub fn fallback_name(base_url: &str, profile: ApiProfile) -> String {
    if profile != UNKNOWN {
        return profile.display_name.to_owned();
    }
    Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| UNKNOWN.display_name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_common_provider_and_adds_https() {
        let profile = infer("", "", "sk-ant-example");
        assert_eq!(profile.display_name, "Anthropic");
        assert_eq!(profile.auth_header, "x-api-key");
        assert_eq!(
            normalize_base_url("api.example.com/v1", "").unwrap(),
            "https://api.example.com/v1"
        );
    }

    #[test]
    fn unknown_provider_can_remain_addressless() {
        // A generic sk- prefix is shared by several providers and must not be
        // guessed as OpenAI without a name or URL.
        let profile = infer("", "", "sk-generic-secret");
        assert_eq!(profile, UNKNOWN);
        assert_eq!(
            normalize_base_url("", profile.default_base_url).unwrap(),
            ""
        );
        assert_eq!(fallback_name("", profile), "API");
    }
}
