//! zizmor's language server.

use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};

use crate::{AuditRegistry, AuditState};

#[derive(Debug)]
struct Backend {
    audit_registry: AuditRegistry,
    client: Client,
}

#[tower_lsp::async_trait]
impl LanguageServer for Backend {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult::default())
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "server initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        tracing::debug!("did_open: {:?}", params);
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        tracing::debug!("did_change: {:?}", params);
    }

    async fn did_save(&self, params: DidSaveTextDocumentParams) {
        tracing::debug!("did_save: {:?}", params);
    }
}

impl Backend {
    async fn analyze(&self, params: TextDocumentItem) {
        // self.client.publish_diagnostics(uri, diags, version)
        todo!()
    }
}

#[tokio::main]
pub(crate) async fn run() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let audit_state = AuditState {
        no_online_audits: false,
        cache_dir: std::env::temp_dir(),
        gh_token: None,
        gh_hostname: crate::GitHubHost::Standard("github.com".into()),
    };

    let (service, socket) = LspService::new(|client| Backend {
        audit_registry: AuditRegistry::default_audits(&audit_state),
        client,
    });
    Server::new(stdin, stdout, socket).serve(service).await;
}
