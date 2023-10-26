<#
.SYNOPSIS
 KEV identifier for AWS Inspector

.DESCRIPTION
   Takes a AWS Inspector report and compares it to CISA's KVE list.
   Script will create a new list of only items that match KEV. 
.PARAMETER


.INPUTS
  NA

.OUTPUTS
  See EXAMPLE OUTPUT below

.NOTES
 
.EXAMPLE
   .\aws-kev.ps1
   -or-
   C:\path\to\script\aws-kev.ps1



#>


#parameters
Param(
 [bool]$deleteSource=$false,
 [bool]$open=$false,
 [bool]$logging=$false,
 [string]$file=''


)
#function to log items
Function LogItem($value,$x){
    if(!($x -eq $false)){
      write-host -ForegroundColor Yellow $value
      write-host ''
      }
   if(!($logDir)){
     return
   }else{
     Add-Content -Path $logPath -Value $value
     Add-content -path $logPath -value ''
   }
}

 Function CleanUp($a){
   LogItem("Attempting to remove "+$a)
   Remove-item -Path $a -ErrorAction SilentlyContinue
   if(test-path $a -ErrorAction SilentlyContinue){
     LogItem("Failed to remove"+$a+". Trying again in 5 seconds..")
     Start-Sleep 5
     Remove-Item -Path $a -ErrorAction SilentlyContinue
     if(test-path $a -ErrorAction SilentlyContinue){
      LogItem("Failed to remove"+$a)
    }else{
      LogItem($a+" removed")
    }
   }
 }
	#Function to get filepath
	Function Get-FilePath($InitialDirectory)
	{
	    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
	  $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
	  $OpenFileDialog.initialDirectory = $initialDirectory
	  $OpenFileDialog.filter = "Excel Files|*.xls;*.xlsx|CSV files (*.csv)|*.csv"
	  $OpenFileDialog.ShowDialog() | Out-Null
	  $filepath = $OpenFileDialog.Filename
	  return $filepath
}

	#Function to get filepath
	Function Save-File($InitialDirectory)
	{
	    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
	  $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
	  $saveFileDialog.initialDirectory = $initialDirectory
	  $saveFileDialog.filter = "CSV (*.csv) | *.csv"
	  $saveFileDialog.ShowDialog() | Out-Null
	  $outpath = $saveFileDialog.Filename
	  return $outpath

}




#end params



#get latest KEV
$kevURI = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
try{
$kev = wget -Uri $kevURI
if($kev.StatusCode -ne 200){
 return "Could not reach CISA KEV list"}else {
 wget -uri $kevURI -OutFile "~/.kevlist.csv"
 $kevList = import-csv "~/.kevlist.csv"
Remove-Item "~/.kevlist.csv"
 }
}catch{return "Could not reach CISA KEV list"}


#openfile
    if($file -eq ''){
     LogItem("Launching OpenFileDialog")

	$csvPath = get-filePath
    }else{
    $csvPath=$file

    }

    LogItem("File Selected: $csvPath")

    #if user cancels picking a file, script will exit
    if($csvPath -eq ''){
    $returnStatement = 'Exiting.. No file loaded.'
    LogItem($returnStatement)
    return $returnStatement
    }

    #if file is excel, convert to csv
    if(($csvPath.split("."))[1] -ne 'csv'){
    
    
#run function
    $outFile = $csvPath.Split(".")[0]+".csv"
    if(test-path $outFile){
    Remove-Item $outFile
    }
    
Function ExcelToCsv ($File) {
    $Excel = New-Object -ComObject Excel.Application
    $wb = $Excel.Workbooks.Open($File)
 
    foreach ($ws in $wb.Worksheets) {
        $ws.SaveAs($outfile, 6)
    }
    $Excel.Quit()
}
 
ExcelToCsv -File $csvPath
#import new csv  	
$csv = import-csv $outFile

#delete temp csv
remove-item $outFile
 
}else {
    #if csv import csv data

    $csv = import-csv $csvPath
}

    LogItem(($csv.Length).toString() +' lines in csv')
    if($csv.Length -gt 10000){
    $totalLines = $csv.Length
    Write-Warning -message "CSV contains $totalLines lines. This script may take a while.."
    }

    #create tempCSV with 4 new columns
    LogItem('Creating tempCSV with new columns')
    $tempCSV = $csv | Select-Object -ErrorAction SilentlyContinue *,@{Name="KEV DUE";expression={''}}
  

 #set vulns object with 0 initial value
 LogItem('Creating aws-kev match csv')


 #loop through each item(line) in csv
 forEach($item in $tempCSV){

    #check if CVE matches KEV
    forEach($kevItem in $kevList){

        #if match, set current item to due date
        if($item.'Vulnerability Id' -eq $kevItem.cveID){
        $item.'KEV DUE' = $kevItem.dueDate
      
        }
    } 

  }


  #create csv of just KEV positive risks
  $awsKev = $tempCSV | ? 'KEV DUE' -NE '' | Sort-Object 'KEV DUE' -Descending
  
  if($awsKev.Count -eq 0){
    Add-Type -AssemblyName Microsoft.VisualBasic
    $MessageBody = "Script did not identify any KEV matches. Script will now exit."
    $MessageTitle = "No Match Found"
    [Microsoft.VisualBasic.Interaction]::MsgBox($MessageBody,'OKOnly,SystemModal,Information', 'No Match Found')
    EXIT
  }

  
  $awsKev | export-csv -NoTypeInformation ~/.temp1.csv
   #Selects certain headers from inspector and puts them in a particular order. 
  $awsKev = import-csv ~/.temp1.csv | Select -ErrorAction SilentlyContinue 'Severity','Fix Available','Finding Type','KEV DUE','Title','Description','Finding ARN','Age (Days)','First Seen','Last Seen''Last Updated','Resource ID','Container Image Tags','Region','Platform','Resource Tags','Affected Packages','Package Installed Version','Fixed in Version','Package Remediation','File Path','Network Paths','Remediation','Inspector Score','Inspector Score Vector','Status','Vulnerability Id','Vendor','Vendor Severity','Vendor Advisory','Vendor Advisory Published','NVD CVSS3 Score','NVD CVSS3 Vector','NVD CVSS2 Score','NVD CVSS2 Vector','Vendor CVSS3 Score','Vendor CVSS3 Vector','Vendor CVSS2 Score','Vendor CVSS2 Vector','Resource Type','Ami','Resource Public Ipv4','Resource Private Ipv4','Resource Ipv6','Resource Vpc','Port Range','Epss Score','Exploit Available','Last Exploited At','Lambda Layers','Lambda Package Type','Lambda Last Updated AtSeverity','Fix Available','Finding Type','KEV DUE','Title','Description','Finding ARN','Age (Days)','First Seen','Last Seen','Last Updated','Resource ID','Container Image Tags','Region','Platform','Resource Tags','Affected Packages','Package Installed Version','Fixed in Version','Package Remediation','File Path','Network Paths','Remediation','Inspector Score','Inspector Score Vector','Status','Vulnerability Id','Vendor','Vendor Severity','Vendor Advisory','Vendor Advisory Published','NVD CVSS3 Score','NVD CVSS3 Vector','NVD CVSS2 Score','NVD CVSS2 Vector','Vendor CVSS3 Score','Vendor CVSS3 Vector','Vendor CVSS2 Score','Vendor CVSS2 Vector','Resource Type','Ami','Resource Public Ipv4','Resource Private Ipv4','Resource Ipv6','Resource Vpc','Port Range','Epss Score','Exploit Available','Last Exploited At','Lambda Layers','Lambda Package Type','Lambda Last Updated At','Reference Urls','Detector Name'

  $outpath = Save-File
  $awsKev | export-csv -LiteralPath $outpath -NoTypeInformation

