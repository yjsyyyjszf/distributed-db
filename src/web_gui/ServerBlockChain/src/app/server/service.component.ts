import {Component, } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {ServerService} from './server.service';

@Component({
  selector: 'app-user',
  templateUrl: './service.component.html',
  styleUrls: ['./service.component.css']
})
export class ServiceComponent{

  private userDataArray = [];
  constructor(private http: HttpClient,
              private service: ServerService) {
  }
  getData(): void {
    this.userDataArray = [];
    this.service.getUserData()
      .subscribe(data => {
        for(const prop in data){
          let buf = prop +": " + data[prop];
          this.userDataArray.push(buf);
        }
        console.log(this.userDataArray);
      });
  }
}
