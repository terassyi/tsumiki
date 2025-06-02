pub trait Decoder<T, D: DecodableFrom<T>> {
    type Error;

    fn decode(&self) -> Result<D, Self::Error>;
}

// Marker trait for its type is capable to be decoded from type T.
pub trait DecodableFrom<T> {}
