use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NORMAL_FRAME_MAX_BYTES: usize = 64 * 1024;
pub const OBSERVATION_FRAME_MAX_BYTES: usize = 512 * 1024;

pub fn encode_frame<T: Serialize>(value: &T, max_bytes: usize) -> Result<Vec<u8>, FrameError> {
    let payload = serde_json::to_vec(value).map_err(FrameError::Json)?;
    if payload.len() > max_bytes {
        return Err(FrameError::Oversized {
            received: payload.len(),
            maximum: max_bytes,
        });
    }
    let payload_length = u32::try_from(payload.len()).map_err(|_| FrameError::Oversized {
        received: payload.len(),
        maximum: max_bytes,
    })?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn decode_single_frame<T: DeserializeOwned>(
    frame: &[u8],
    max_bytes: usize,
) -> Result<T, FrameError> {
    if frame.len() < 4 {
        return Err(FrameError::IncompleteHeader);
    }
    let declared = usize::try_from(u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]))
        .map_err(|_| FrameError::Oversized {
            received: frame.len().saturating_sub(4),
            maximum: max_bytes,
        })?;
    if declared > max_bytes {
        return Err(FrameError::Oversized {
            received: declared,
            maximum: max_bytes,
        });
    }
    let expected = declared.checked_add(4).ok_or(FrameError::LengthOverflow)?;
    if frame.len() < expected {
        return Err(FrameError::IncompletePayload {
            declared,
            available: frame.len().saturating_sub(4),
        });
    }
    if frame.len() > expected {
        return Err(FrameError::TrailingBytes(frame.len() - expected));
    }
    let json = std::str::from_utf8(&frame[4..]).map_err(FrameError::Utf8)?;
    serde_json::from_str(json).map_err(FrameError::Json)
}

pub async fn read_frame<T, R>(reader: &mut R, max_bytes: usize) -> Result<T, FrameError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .await
        .map_err(FrameError::Io)?;
    let declared =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| FrameError::Oversized {
            received: usize::MAX,
            maximum: max_bytes,
        })?;
    if declared > max_bytes {
        return Err(FrameError::Oversized {
            received: declared,
            maximum: max_bytes,
        });
    }
    let mut frame = Vec::with_capacity(declared.saturating_add(4));
    frame.extend_from_slice(&header);
    frame.resize(declared.saturating_add(4), 0);
    reader
        .read_exact(&mut frame[4..])
        .await
        .map_err(FrameError::Io)?;
    decode_single_frame(&frame, max_bytes)
}

pub async fn write_frame<T, W>(
    writer: &mut W,
    value: &T,
    max_bytes: usize,
) -> Result<(), FrameError>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let frame = encode_frame(value, max_bytes)?;
    writer.write_all(&frame).await.map_err(FrameError::Io)
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame header is incomplete")]
    IncompleteHeader,
    #[error("frame payload is incomplete: declared {declared}, available {available}")]
    IncompletePayload { declared: usize, available: usize },
    #[error("frame length overflowed")]
    LengthOverflow,
    #[error("frame contains {0} trailing bytes")]
    TrailingBytes(usize),
    #[error("frame is oversized: received {received}, maximum {maximum}")]
    Oversized { received: usize, maximum: usize },
    #[error("frame payload is not UTF-8: {0}")]
    Utf8(std::str::Utf8Error),
    #[error("frame JSON is invalid: {0}")]
    Json(serde_json::Error),
    #[error("frame transport failed: {0}")]
    Io(std::io::Error),
}
