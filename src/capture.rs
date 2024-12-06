use crate::blocks::PcapBlock;
use crate::error::PcapError;
use crate::linktype::Linktype;
use crate::pcap::parse_pcap_header;
use crate::pcapng::parse_sectionheaderblock;
use crate::traits::PcapReaderIterator;
use crate::{LegacyPcapReader, PcapNGReader};
use circular::Buffer;
use nom::Needed;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Generic interface for PCAP or PCAPNG file access
pub trait Capture {
    fn get_datalink(&self) -> Linktype;

    fn get_snaplen(&self) -> u32;

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = PcapBlock<'a>> + 'a>;
}

/// Get a generic `PcapReaderIterator`, given a `Read` input. The input is probed for pcap-ng first,
/// then pcap.
///
/// ```rust
/// #[tokio::main]
/// async fn main() {
///     let path = "assets/ntp.pcap";
///     let file = tokio::fs::File::open(path).await.expect("File open failed");
///     let mut reader = pcap_parser::create_reader(65536, file).await.expect("LegacyPcapReader");
///     let _ = reader.next();
/// }
/// ```
pub async fn create_reader<'b, R>(
    capacity: usize,
    mut reader: R,
) -> Result<Box<dyn PcapReaderIterator + 'b>, PcapError<&'static [u8]>>
where
    R: AsyncRead + Unpin + Send + 'b,
{
    let mut buffer = Buffer::with_capacity(capacity);
    let sz = reader
        .read(buffer.space())
        .await
        .or(Err(PcapError::ReadError))?;
    if sz == 0 {
        return Err(PcapError::Eof);
    }
    buffer.fill(sz);
    // just check that first block is a valid one
    if parse_sectionheaderblock(buffer.data()).is_ok() {
        return PcapNGReader::from_buffer(buffer, reader)
            .await
            .map(|r| Box::new(r) as Box<dyn PcapReaderIterator>);
    }
    match parse_pcap_header(buffer.data()) {
        Ok(_) => LegacyPcapReader::from_buffer(buffer, reader)
            .await
            .map(|r| Box::new(r) as Box<dyn PcapReaderIterator>),
        Err(nom::Err::Incomplete(Needed::Size(n))) => Err(PcapError::Incomplete(n.into())),
        Err(nom::Err::Incomplete(Needed::Unknown)) => Err(PcapError::Incomplete(0)),
        _ => Err(PcapError::HeaderNotRecognized),
    }
}
