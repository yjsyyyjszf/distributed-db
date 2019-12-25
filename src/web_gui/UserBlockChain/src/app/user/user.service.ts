import {Injectable} from '@angular/core';
import {HttpClient, } from '@angular/common/http';

@Injectable({
  providedIn: 'root',
})

export class UserService {
  constructor(private http: HttpClient) {}

  postDataUser(data: string): boolean {
    let isOk = true;
    this.http.request('POST', 'http://192.168.0.107:4000/interfaceData', {body: data}).subscribe(
      x => {
        console.log('ok' + x);
      }
      , e => {
        console.log('error: ' + e);
        isOk = false;
      }
    );
    return isOk;
  }

  postPropertyUser(property: object): boolean {
    let isOk = true;
    this.http.request('POST', 'http://192.168.0.107:4000/interfaceAccess', {body: JSON.stringify(property)}).subscribe(
      x => {
        console.log('ok' + x);
      }
      , e => {
        console.log('error: ' + e);
        isOk = false;
      }
    );
    return isOk;
  }
}
