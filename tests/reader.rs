use pcap_parser::{create_reader, PcapError};

#[tokio::test]
async fn test_empty_reader_error() {
    let empty: &[u8] = &[];
    let res = create_reader(1024, empty).await;
    assert!(res.is_err());
    if let Err(err) = res {
        assert_eq!(err, PcapError::Eof);
    } else {
        unreachable!();
    }
}

#[tokio::test]
async fn test_empty_reader_incomplete() {
    let empty: &[u8] = &[0];
    let res = create_reader(1024, empty).await;
    assert!(res.is_err());
    if let Err(err) = res {
        assert!(matches!(err, PcapError::Incomplete(_)));
    } else {
        unreachable!();
    }
}
