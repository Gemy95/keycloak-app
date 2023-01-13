import { IsNotEmpty, IsString } from 'class-validator';
import { Field, ArgsType } from '@nestjs/graphql';

@ArgsType()
export class LoginUserInput {
  @Field()
  @IsNotEmpty()
  @IsString()
  username: string;

  @Field()
  @IsNotEmpty()
  @IsString()
  password: string;

  // @Field()
  // @IsNotEmpty()
  // @IsString()
  // mobile: string;
}
