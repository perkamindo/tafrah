use tafrah_traits::Error;

pub(crate) fn build_context_prefix(ctx: &[u8]) -> Result<([u8; 257], usize), Error> {
    if ctx.len() > u8::MAX as usize {
        return Err(Error::InvalidParameter);
    }

    let mut pre = [0u8; 257];
    pre[1] = ctx.len() as u8;
    pre[2..2 + ctx.len()].copy_from_slice(ctx);

    Ok((pre, 2 + ctx.len()))
}
