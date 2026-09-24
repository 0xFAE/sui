use tokio::time::{Instant, sleep};

use super::common::{MYSTICETI_REMAINING_EPOCH_MS, Scenario, ms, network_profile};

pub async fn run(scenario: Scenario) {
    let start = Instant::now();
    sleep(std::time::Duration::from_millis(
        MYSTICETI_REMAINING_EPOCH_MS,
    ))
    .await;
    let elapsed = start.elapsed();

    println!(
        "SNAPPER_UNLOCK_SIM_RESULT protocol=mysticeti_fpc scenario={} profile={} conflict_to_object_usable_ms={} remaining_epoch_ms={} reconfiguration_ms=0",
        scenario.code(),
        network_profile(),
        ms(elapsed),
        MYSTICETI_REMAINING_EPOCH_MS,
    );
}
