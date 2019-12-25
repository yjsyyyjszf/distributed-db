import {Component, } from '@angular/core';
import {HttpClient} from '@angular/common/http';
import {UserService} from './user.service';

interface Property {
  writeRights: boolean;
  readRights: boolean;
}

@Component({
  selector: 'app-user',
  templateUrl: './user.component.html',
  styleUrls: ['./user.component.css']
})
export class UserComponent{

  private data: string;
  private propertyUser: Property = {
    writeRights: false,
    readRights: false
  };

  constructor(private http: HttpClient,
              private service: UserService) {
  }

  public postData(): void {
    console.log(this.data);
    this.service.postDataUser(this.data);
  }

  public postProperty(): void {
    console.log(this.propertyUser);
    this.service.postPropertyUser(this.propertyUser);
  }

  public writeData(): void {
    console.log(!this.propertyUser.writeRights);
    this.propertyUser.writeRights = !this.propertyUser.writeRights;
  }

  public readData(): void {
    console.log(!this.propertyUser.readRights);
    this.propertyUser.readRights = !this.propertyUser.readRights;
  }
}
