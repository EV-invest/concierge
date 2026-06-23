use evconcierge_contracts::concierge::v1::{SendNotificationRequest, SendNotificationResponse, notification_service_server::NotificationService};
use tonic::{Request, Response, Status};

/// The notification module. DEFERRED — declared so the surface and wire contract
/// exist; the delivery channels (email/push/…) land later.
#[derive(Default)]
pub struct Notifications;

impl Notifications {
	pub fn new() -> Self {
		Self
	}
}

#[tonic::async_trait]
impl NotificationService for Notifications {
	async fn send(&self, _request: Request<SendNotificationRequest>) -> Result<Response<SendNotificationResponse>, Status> {
		Err(Status::unimplemented("NotificationService.Send is not implemented"))
	}
}
