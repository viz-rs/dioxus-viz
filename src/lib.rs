//! Dioxus utilities for the [Viz](https://docs.rs/viz/latest) server framework.
//!
//! # Example
//! ```rust
//! use dioxus::prelude::*;
//! use dioxus_fullstack::prelude::*;
//! use dioxus_viz::*;
//! use viz::{serve, Router};
//!
//! fn main() {
//!     #[cfg(feature = "web")]
//!     // Hydrate the application on the client
//!     dioxus_web::launch_cfg(app, dioxus_web::Config::new().hydrate(true));
//!     #[cfg(feature = "ssr")]
//!     {
//!         tokio::runtime::Runtime::new()
//!             .unwrap()
//!             .block_on(async move {
//!                 let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
//!                 let listener = tokio::net::TcpListener::bind(addr).await?;
//!                 serve(
//!                     listener,
//!                     Router::new()
//!                         // Server side render the application, serve static assets, and register server functions
//!                         .serve_dioxus_application("", ServeConfigBuilder::new(app, ()))
//!                 )
//!                 .await
//!                 .unwrap();
//!             });
//!      }
//! }
//!
//! fn app(cx: Scope) -> Element {
//!     let text = use_state(cx, || "...".to_string());
//!
//!     cx.render(rsx! {
//!         button {
//!             onclick: move |_| {
//!                 to_owned![text];
//!                 async move {
//!                     if let Ok(data) = get_server_data().await {
//!                         text.set(data);
//!                     }
//!                 }
//!             },
//!             "Run a server function"
//!         }
//!         "Server said: {text}"
//!     })
//! }
//!
//! #[server(GetServerData)]
//! async fn get_server_data() -> Result<String, ServerFnError> {
//!     Ok("Hello from the server!".to_string())
//! }
//! ```

use dioxus_fullstack::{prelude::*, server_fn_service};
use http_body_util::{BodyExt, Full};
use server_fn::{Encoding, ServerFunctionRegistry};
use std::sync::{Arc, RwLock};
use viz::{
    header, types::State, Body, Error, Handler, HandlerExt, IntoResponse, Request, RequestExt,
    Response, ResponseExt, Result, Router, StatusCode,
};

/// A extension trait with utilities for integrating Dioxus with your Viz router.
pub trait DioxusRouterExt {
    /// Registers server functions with a custom handler function. This allows you to pass custom context to your server functions by generating a [`DioxusServerContext`] from the request.
    ///
    /// # Example
    /// ```rust,no_run
    /// use std::sync::{Arc, RwLock};
    /// use dioxus::prelude::*;
    /// use dioxus_fullstack::{prelude::*, server_fn_service};
    /// use dioxus_viz::*;
    /// use http_body_util::BodyExt;
    /// use viz::{serve, IntoResponse, Request, Router, StatusCode,};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    ///    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    ///    serve(
    ///        listener,
    ///        Router::new()
    ///            .register_server_fns_with_handler("", |func| {
    ///                move |req: Request| {
    ///                    let mut service = server_fn_service(Default::default(), func.clone());
    ///                    let (parts, body) = req.into_parts();
    ///                    async move {
    ///                        let body = body.collect().await.unwrap_or_default().to_bytes().into();
    ///                        let req = Request::from_parts(parts, body);
    ///                        match service.run(req).await {
    ///                            Ok(res) => Ok(res.map(Into::into)),
    ///                            Err(e) => {
    ///                                Ok((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
    ///                            }
    ///                        }
    ///                    }
    ///                }
    ///            })
    ///    )
    ///    .await
    ///    .unwrap();
    /// }
    /// ```
    fn register_server_fns_with_handler<F, H, O>(
        self,
        server_fn_route: &'static str,
        handler: F,
    ) -> Self
    where
        F: FnMut(server_fn::ServerFnTraitObj<()>) -> H,
        H: Handler<Request, Output = Result<O>> + Clone,
        O: IntoResponse + Send + 'static;

    /// Registers server functions with the default handler. This handler function will pass an empty [`DioxusServerContext`] to your server functions.
    ///
    /// # Example
    /// ```rust,no_run
    /// use dioxus::prelude::*;
    /// use dioxus_fullstack::prelude::*;
    /// use dioxus_viz::*;
    /// use viz::{serve, Router};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    ///     let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    ///     serve(
    ///         listener,
    ///         Router::new()
    ///             // Register server functions routes with the default handler
    ///             .register_server_fns("")
    ///     )
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    fn register_server_fns(self, server_fn_route: &'static str) -> Self;

    /// Register the web RSX hot reloading endpoint. This will enable hot reloading for your application in debug mode when you call [`dioxus_hot_reload::hot_reload_init`].
    ///
    /// # Example
    /// ```rust,no_run
    /// use dioxus_fullstack::prelude::*;
    /// use dioxus_viz::*;
    /// use viz::{serve, Router};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    ///     let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    ///     serve(
    ///         listener,
    ///         Router::new()
    ///             // Connect to hot reloading in debug mode
    ///             .connect_hot_reload()
    ///     )
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    fn connect_hot_reload(self) -> Self;

    /// Serves the static WASM for your Dioxus application (except the generated index.html).
    ///
    /// # Example
    /// ```rust,no_run
    /// use dioxus::prelude::*;
    /// use dioxus_fullstack::prelude::*;
    /// use dioxus_viz::*;
    /// use viz::{serve, Router};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    ///     let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    ///     serve(
    ///         listener,
    ///         Router::new()
    ///             // Server side render the application, serve static assets, and register server functions
    ///             .serve_static_assets("dist")
    ///     )
    ///     .await
    ///     .unwrap();
    /// }
    ///
    /// fn app(cx: Scope) -> Element {
    ///     todo!()
    /// }
    /// ```
    fn serve_static_assets<P>(self, assets_path: P) -> Self
    where
        P: Into<std::path::PathBuf>;

    /// Serves the Dioxus application. This will serve a complete server side rendered application.
    /// This will serve static assets, server render the application, register server functions, and intigrate with hot reloading.
    ///
    /// # Example
    /// ```rust,no_run
    /// use dioxus::prelude::*;
    /// use dioxus_fullstack::prelude::*;
    /// use dioxus_viz::*;
    /// use viz::{serve, Router};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
    ///     let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    ///     serve(
    ///         listener,
    ///         Router::new()
    ///             // Server side render the application, serve static assets, and register server functions
    ///             .serve_dioxus_application("", ServeConfigBuilder::new(app, ()))
    ///     )
    ///     .await
    ///     .unwrap();
    /// }
    ///
    /// fn app(cx: Scope) -> Element {
    ///     todo!()
    /// }
    /// ```
    fn serve_dioxus_application<P, C>(self, server_fn_route: &'static str, cfg: C) -> Self
    where
        P: Clone + serde::Serialize + Send + Sync + 'static,
        C: Into<ServeConfig<P>>;
}

impl DioxusRouterExt for Router {
    fn register_server_fns_with_handler<F, H, O>(
        self,
        server_fn_route: &'static str,
        mut handler: F,
    ) -> Self
    where
        F: FnMut(server_fn::ServerFnTraitObj<()>) -> H,
        H: Handler<Request, Output = Result<O>> + Clone,
        O: IntoResponse + Send + 'static,
    {
        let mut router = self;
        for server_fn_path in DioxusServerFnRegistry::paths_registered() {
            let func = DioxusServerFnRegistry::get(server_fn_path).unwrap();
            let full_route = format!("{server_fn_route}/{server_fn_path}");
            match func.encoding() {
                Encoding::Url | Encoding::Cbor => {
                    router = router.post(&full_route, handler(func));
                }
                Encoding::GetJSON | Encoding::GetCBOR => {
                    router = router.get(&full_route, handler(func));
                }
            }
        }
        router
    }

    fn register_server_fns(self, server_fn_route: &'static str) -> Self {
        self.register_server_fns_with_handler(server_fn_route, |func| {
            move |req: Request| {
                let mut service = server_fn_service(Default::default(), func.clone());
                let (parts, body) = req.into_parts();
                async move {
                    let body = body.collect().await.unwrap_or_default().to_bytes().into();
                    let req = Request::from_parts(parts, body);
                    match service.run(req).await {
                        Ok(res) => Ok(res.map(Into::into)),
                        Err(e) => {
                            Ok((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
                        }
                    }
                }
            }
        })
    }

    fn serve_static_assets<P>(mut self, assets_path: P) -> Self
    where
        P: Into<std::path::PathBuf>,
    {
        use viz::handlers::serve::{Dir, File};

        let assets_path = assets_path.into();

        // Serve all files in dist folder except index.html
        let dir = std::fs::read_dir(&assets_path).unwrap_or_else(|e| {
            panic!(
                "Couldn't read assets directory at {:?}: {}",
                &assets_path, e
            )
        });

        for entry in dir.flatten() {
            let path = entry.path();
            if path.ends_with("index.html") {
                continue;
            }
            let route = path
                .strip_prefix(&assets_path)
                .unwrap()
                .iter()
                .map(|segment| {
                    segment.to_str().unwrap_or_else(|| {
                        panic!("Failed to convert path segment {:?} to string", segment)
                    })
                })
                .collect::<Vec<_>>()
                .join("/");
            let route = format!("/{}", route);
            if path.is_dir() {
                self = self.get(&route, Dir::new(path));
            } else {
                self = self.get(&route, File::new(path));
            }
        }

        self
    }

    fn serve_dioxus_application<P, C>(self, server_fn_route: &'static str, cfg: C) -> Self
    where
        P: Clone + serde::Serialize + Send + Sync + 'static,
        C: Into<ServeConfig<P>>,
    {
        let cfg = cfg.into();
        let ssr_state = SSRState::new(&cfg);

        // Add server functions and render index.html
        self.serve_static_assets(cfg.assets_path)
            .connect_hot_reload()
            .register_server_fns(server_fn_route)
            .get("*", render_handler::<P>.with(State::new((cfg, ssr_state))))
    }

    fn connect_hot_reload(self) -> Self {
        #[cfg(all(debug_assertions, feature = "hot-reload", feature = "ssr"))]
        {
            self.nest(
                "/_dioxus",
                Router::new()
                    .get("/disconnect", |ws: viz::types::WebSocket| async {
                        ws.on_upgrade(|mut ws| async move {
                            use viz::types::Message;
                            let _ = ws.send(Message::Text("connected".into())).await;
                            loop {
                                if ws.recv().await.is_none() {
                                    break;
                                }
                            }
                        })
                    })
                    .get("/hot_reload", hot_reload_handler),
            )
        }
        #[cfg(not(all(debug_assertions, feature = "hot-reload", feature = "ssr")))]
        {
            self
        }
    }
}

fn apply_request_parts_to_response(headers: header::HeaderMap, response: &mut Response) {
    let mut_headers = response.headers_mut();
    for (key, value) in headers.iter() {
        mut_headers.insert(key, value.clone());
    }
}

/// SSR renderer handler for Viz with added context injection.
///
/// # Example
/// ```rust,no_run
/// use std::sync::{Arc, Mutex};
/// use dioxus::prelude::*;
/// use dioxus_fullstack::prelude::*;
/// use dioxus_viz::*;
/// use viz::{types::State, serve, HandlerExt, Router};
///
/// fn app(cx: Scope) -> Element {
///     render! {
///         "hello!"
///     }
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let cfg = ServeConfigBuilder::new(app, ())
///         .assets_path("dist")
///         .build();
///     let ssr_state = SSRState::new(&cfg);
///
///     // This could be any state you want to be accessible from your server
///     // functions using `[DioxusServerContext::get]`.
///     let state = Arc::new(Mutex::new("state".to_string()));
///
///     let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
///     let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
///     serve(
///         listener,
///         Router::new()
///             // Register server functions, etc.
///             // Note you probably want to use `register_server_fns_with_handler`
///             // to inject the context into server functions running outside
///             // of an SSR render context.
///             .get("*", render_handler_with_context::<(), fn(&mut DioxusServerContext)>
///                 .with(State::new((cfg, ssr_state)))
///                 .with(State::new(
///                     move |ctx: &mut DioxusServerContext| ctx.insert(state.clone()).unwrap(),
///                 ))
///             )
///     )
///     .await
///     .unwrap();
/// }
/// ```
pub async fn render_handler_with_context<P, F>(req: Request) -> Result<Response>
where
    P: Clone + serde::Serialize + Send + Sync + 'static,
    F: FnMut(&mut DioxusServerContext) + Clone + Send + Sync + 'static,
{
    let (cfg, ssr_state) = req.state::<(ServeConfig<P>, SSRState)>().unwrap();
    let mut inject_context = req.state::<F>().unwrap();
    let (parts, _) = req.into_parts();
    let url = parts.uri.path_and_query().unwrap().to_string();
    let parts: Arc<RwLock<http::request::Parts>> = Arc::new(RwLock::new(parts.into()));
    let mut server_context = DioxusServerContext::new(parts.clone());
    inject_context(&mut server_context);

    match ssr_state.render(url, &cfg, &server_context).await {
        Ok(RenderResponse { html, freshness }) => {
            let mut response = Response::html(html);
            freshness.write(response.headers_mut());
            let headers = server_context.response_parts().unwrap().headers.clone();
            apply_request_parts_to_response(headers, &mut response);
            Ok(response)
        }
        Err(e) => {
            tracing::error!("Failed to render page: {}", e);
            Ok(report_err(e))
        }
    }
}

/// SSR renderer handler for Viz.
pub async fn render_handler<P>(mut req: Request) -> Result<Response>
where
    P: Clone + serde::Serialize + Send + Sync + 'static,
{
    req.set_state::<fn(&mut DioxusServerContext)>(|_: &mut _| ())
        .expect("the fn should be saved");
    render_handler_with_context::<P, fn(&mut DioxusServerContext)>(req).await
}

fn report_err<E: std::fmt::Display>(e: E) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("Error: {}", e)).into_response()
}

/// A handler for Dioxus web hot reload websocket. This will send the updated static parts of the RSX to the client when they change.
#[cfg(all(debug_assertions, feature = "hot-reload", feature = "ssr"))]
pub async fn hot_reload_handler(ws: viz::types::WebSocket) -> impl IntoResponse {
    use futures_util::StreamExt;
    use viz::types::Message;

    let state = crate::hot_reload::spawn_hot_reload().await;

    ws.on_upgrade(move |mut socket| async move {
        println!("🔥 Hot Reload WebSocket connected");
        {
            // update any rsx calls that changed before the websocket connected.
            {
                println!("🔮 Finding updates since last compile...");
                let templates_read = state.templates.read().await;

                for template in &*templates_read {
                    if socket
                        .send(Message::Text(serde_json::to_string(&template).unwrap()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            println!("finished");
        }

        let mut rx =
            tokio_stream::wrappers::WatchStream::from_changes(state.message_receiver.clone());
        while let Some(change) = rx.next().await {
            if let Some(template) = change {
                let template = { serde_json::to_string(&template).unwrap() };
                if socket.send(Message::Text(template)).await.is_err() {
                    break;
                };
            }
        }
    })
}
