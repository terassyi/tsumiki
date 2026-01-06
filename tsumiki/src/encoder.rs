pub trait Encoder<T, E: EncodableTo<T>> {
    type Error;

    fn encode(&self) -> Result<E, Self::Error>;
}

pub trait EncodableTo<T> {}
