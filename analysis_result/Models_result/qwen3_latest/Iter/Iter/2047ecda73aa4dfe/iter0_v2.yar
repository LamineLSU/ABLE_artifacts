rule ExitProcessCall
{
    meta:
        description = "Identifies a direct call to ExitProcess, likely triggered by sandbox detection."
        cape_options = "bp0=$a+0,action0=skip,count=0"
    strings:
        $a = { 53 FF 15 ?? ?? ?? ?? } // push ebx + call to ExitProcess (displacement replaced with ??)
    condition:
        $a
}