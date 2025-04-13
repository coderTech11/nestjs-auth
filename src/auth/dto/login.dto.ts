import { IsEmail, IsString, IsOptional } from 'class-validator';

export class loginDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsOptional()
  @IsString()
  otp?: string;
}
