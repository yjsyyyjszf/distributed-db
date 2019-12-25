import {Injectable} from '@angular/core';
import {HttpClient, } from '@angular/common/http';
import {Observable} from "rxjs";

@Injectable({
  providedIn: 'root',
})

export class ServerService {
  constructor(private http: HttpClient) {}

  getUserData (): Observable<any>{
    return this.http.get('http://192.168.43.128:4001/interfaceData');
  }
}
