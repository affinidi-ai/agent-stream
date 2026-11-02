use crate::world::SurfaceWorld;

pub(crate) fn caller_response(world: &SurfaceWorld) -> &crate::bdd_support::admin_client::RecordedResponse {
    world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded")
}
