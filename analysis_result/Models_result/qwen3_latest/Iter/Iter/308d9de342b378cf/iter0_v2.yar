rule ExitProcessCall
{
    meta:
        description = "Call to ExitProcess"
        cape_options = "bp0=$call+0,action0=skip,count=0"
    strings:
        $call = { E8 ?? ?? ?? ?? }
    condition:
        $call
}