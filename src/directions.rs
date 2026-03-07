#![allow(dead_code)]

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum IncomingDirection {
    FromServer,
    FromClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum OutgoingDirection {
    ToServer,
    ToClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub(crate) enum Direction {
    Incoming(IncomingDirection),
    Outgoing(OutgoingDirection),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct DataEvent<'a, T> {
    pub(crate) direction: T,
    pub(crate) buffer: &'a [u8],
}

pub type IncomingDataEvent<'a> = DataEvent<'a, IncomingDirection>;
pub type OutgoingDataEvent<'a> = DataEvent<'a, OutgoingDirection>;
