pub(crate) trait Encoder<T, E: EncodableTo<T>> {
    type Error;

    fn encode(&self) -> Result<E, Self::Error>;
}

pub(crate) trait EncodableTo<T> {}
