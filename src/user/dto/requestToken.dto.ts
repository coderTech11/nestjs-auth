import { IsEmail, IsString } from 'class-validator';

export class RequestTokenDto {
  @IsString()
  @IsEmail()
  email: string;
}
