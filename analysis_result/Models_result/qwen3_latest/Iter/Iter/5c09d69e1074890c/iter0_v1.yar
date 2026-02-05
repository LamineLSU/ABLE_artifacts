rule ExitProcessDetection
{
    meta:
        description = "Detects a call to ExitProcess via a sequence of register manipulation and function call"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 52 8B 55 ?? 52 FF D0 }
    condition:
        $a
}