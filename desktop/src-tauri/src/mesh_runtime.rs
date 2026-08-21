/// Install the larger worker stacks required by mesh-llm's deeply nested
/// asynchronous model download and node-management futures.
pub fn install() {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(crate::mesh_llm::MESH_WORKER_STACK_SIZE)
        .build()
    {
        Ok(runtime) => {
            tauri::async_runtime::set(runtime.handle().clone());
            // Tauri owns the handle for the process lifetime after this point.
            std::mem::forget(runtime);
            eprintln!(
                "buzz-mesh: installed tokio runtime with {} MiB worker stacks",
                crate::mesh_llm::MESH_WORKER_STACK_SIZE / (1024 * 1024)
            );
        }
        Err(error) => {
            eprintln!("buzz-mesh: failed to build big-stack tokio runtime, using default: {error}");
        }
    }
}
