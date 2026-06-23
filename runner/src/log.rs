use evconcierge_contracts::concierge::v1::{AppendLogRequest, AppendLogResponse, log_service_server::LogService};
use tonic::{Request, Response, Status};

/// The platform log module. DEFERRED — declared so the surface and wire contract
/// exist; the append-only sink lands later.
#[derive(Default)]
pub struct Logs;

impl Logs {
	pub fn new() -> Self {
		Self
	}
}

#[tonic::async_trait]
impl LogService for Logs {
	async fn append(&self, _request: Request<AppendLogRequest>) -> Result<Response<AppendLogResponse>, Status> {
		Err(Status::unimplemented("LogService.Append is not implemented"))
	}
}
