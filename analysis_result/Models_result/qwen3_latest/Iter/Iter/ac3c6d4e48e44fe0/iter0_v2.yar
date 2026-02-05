rule Pattern1
{
    meta:
        description = "Call to CloseHandle and subsequent instructions leading to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { E8 ?? ?? ?? ?? } 53 { E8 ?? ?? ?? ?? }
    condition:
        $a
}