"""SQL gateway extension patches for ADG.

Everything the SQL gateway needs on top of upstream ADG lives in this package; upstream files only
get small, guarded hook calls. With ``ADG_EXT_ENABLED`` off, upstream behavior is unchanged.
"""
