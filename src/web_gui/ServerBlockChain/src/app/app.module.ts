import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { AppComponent } from './app.component';


import { AppRoutingModule } from './app-routing.module';
import { ServiceComponent } from './server/service.component';

@NgModule({
  imports: [
    BrowserModule,
    FormsModule,
    AppRoutingModule,
    HttpClientModule
  ],
  declarations: [
    AppComponent,
    ServiceComponent
  ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }
