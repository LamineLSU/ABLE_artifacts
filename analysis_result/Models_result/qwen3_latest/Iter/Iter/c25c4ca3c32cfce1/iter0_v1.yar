rule ExitProcess_Call
{
    meta:
        description = "Detects a direct call to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
        author = "Your Name"
        date = "2025-03-15"
    strings:
        $a = { 83 C4 14 52 FF D0 5E }
    condition:
        $a
}