rule IOPortAccessCheck
{
    meta:
        description = "Detects I/O port access followed by a conditional jump (JNP) that may be used to bypass security checks."
        cape_options = "bp0=$io+0,action0=skip,count=0"
        author = "security@yourteam.com"
    strings:
        $io = { E5 62 7B ?? 5E 5D C3 }
    condition:
        $io
}