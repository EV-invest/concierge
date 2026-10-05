use heck::ToSnakeCase;
use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitStr, parse_macro_input};

/// `#[permission("ns:resource")]` on a fieldless enum: each variant is the permission
/// `ns:resource:<snake_case(variant)>`.
#[proc_macro_derive(Permission, attributes(permission))]
pub fn derive_permission(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	match expand(&input) {
		Ok(tokens) => tokens.into(),
		Err(e) => e.to_compile_error().into(),
	}
}

fn expand(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
	let ident = &input.ident;
	let Data::Enum(data) = &input.data else {
		return Err(syn::Error::new_spanned(ident, "Permission is derived on an enum"));
	};
	let attr = input
		.attrs
		.iter()
		.find(|a| a.path().is_ident("permission"))
		.ok_or_else(|| syn::Error::new_spanned(ident, "missing #[permission(\"<namespace>:<resource…>\")]"))?;
	let prefix: LitStr = attr.parse_args()?;
	let value = prefix.value();
	let segments: Vec<&str> = value.split(':').collect();
	if segments.len() < 2 || !segments.iter().all(|s| is_segment(s)) {
		return Err(syn::Error::new_spanned(&prefix, "expected `<namespace>:<resource…>`, segments of [a-z0-9_]"));
	}
	let mut arms = Vec::new();
	let mut names = Vec::new();
	for variant in &data.variants {
		if !matches!(variant.fields, Fields::Unit) {
			return Err(syn::Error::new_spanned(variant, "a permission variant carries no data"));
		}
		let v = &variant.ident;
		let name = format!("{value}:{}", v.to_string().to_snake_case());
		arms.push(quote! { Self::#v => #name });
		names.push(name);
	}
	Ok(quote! {
		impl #ident {
			pub const fn as_str(self) -> &'static str {
				match self { #(#arms,)* }
			}
		}
		impl ::concierge_iam::Permission for #ident {
			fn as_str(self) -> &'static str {
				#ident::as_str(self)
			}
		}
		#(::concierge_iam::__submit! { ::concierge_iam::Entry::Permission(#names) })*
	})
}

fn is_segment(s: &str) -> bool {
	!s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
