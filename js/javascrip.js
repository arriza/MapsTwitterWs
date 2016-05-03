/**
 * Created by unai on 27/04/2016.
 */

function GetParameters(){
    var eskaera=new XMLHttpRequest();

    eskaera.onreadystatechange=function () {
        if(eskaera.readyState==4) {
            if(eskaera.status==200) {
                if (eskaera.responseText != null) {
                    var jsonObj = JSON.parse(eskaera.responseText);
                    document.getElementsByClassName("year")[0].innerHTML=jsonObj.year;
                    document.getElementsByClassName("month")[0].innerHTML=jsonObj.month;
                    document.getElementsByClassName("day")[0].innerHTML=jsonObj.day;
                    document.getElementsByClassName("hour")[0].innerHTML=jsonObj.hour;
                    document.getElementsByClassName("minute")[0].innerHTML=jsonObj.minute;
                    document.getElementsByClassName("second")[0].innerHTML=jsonObj.second;
                }
            }
        }
    }

    eskaera.open("GET", "/orduaAldiune", true);
    eskaera.send(null);
    setTimeout("GetTimeIO()",5000);
}
